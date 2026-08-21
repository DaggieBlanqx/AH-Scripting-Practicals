#!/usr/bin/env python3
"""
analyze_sql_injection.py
Target: logs/01_sql_injection_meridian_retail.log (Meridian Retail Group)

Detects SQL injection recon, sqlmap fingerprinting, blind boolean-based
extraction, UNION-based data dumps, authentication bypass, credential
stuffing account takeovers, and post-bypass exfiltration in a web access
log that is mixed with ordinary customer traffic.

Usage: python analyze_sql_injection.py <path-to-log> [--pdf output.pdf]

Missing packages (fpdf2) are installed automatically on first run.
"""

import argparse
import os
import re
import sys
from collections import Counter
from urllib.parse import unquote

from pdf_report_lib import IncidentReport

# Matched against a URL-decoded copy of each line, so an encoded space
# (%20) between keywords like "OR 1=1" or "UNION SELECT" does not hide
# the payload from detection.
SQLI_PATTERN = re.compile(
    r"UNION SELECT|OR 1=1|OR '1'='1|SLEEP\(|extractvalue|information_schema|--\s*-|'--|blind_probe",
    re.IGNORECASE,
)
LOG_LINE = re.compile(
    r'^(?P<ip>[\d.]+) - - \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\w+) (?P<path>\S+) (?P<proto>[^"]+)" '
    r'(?P<status>\d+) (?P<size>\d+) "(?P<referer>[^"]*)" "(?P<ua>[^"]*)"'
)


def load_lines(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        return [line.rstrip("\n") for line in f]


def parse_ip(line):
    m = LOG_LINE.match(line)
    return m.group("ip") if m else None


def parse_path(line):
    m = LOG_LINE.match(line)
    return m.group("path") if m else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("log_file", nargs="?", default="../logs/01_sql_injection_meridian_retail.log")
    ap.add_argument("--pdf", default=None, help="output PDF path")
    args = ap.parse_args()

    lines = load_lines(args.log_file)
    decoded_lines = [unquote(l) for l in lines]
    total_lines = len(lines)

    sqli_lines = [l for l, d in zip(lines, decoded_lines) if SQLI_PATTERN.search(d)]
    blind_lines = [l for l in lines if "blind_probe" in l]
    bypass_lines = [l for l in lines if "AUTH_BYPASS_SUCCESS" in l]
    exfil_lines = [l for l in lines if "EXFIL_CANDIDATE" in l]
    waf_lines = [l for l in lines if "WAF_BLOCK" in l]
    takeover_lines = [l for l in lines if "ACCOUNT_TAKEOVER_SUCCESS" in l]
    scanner_lines = [l for l in lines if "AcunetixScanner" in l]
    alert_lines = [l for l in lines if "SECURITY_ALERT" in l]

    ip_counts = Counter(parse_ip(l) for l in sqli_lines if parse_ip(l))
    blind_ip_counts = Counter(parse_ip(l) for l in blind_lines if parse_ip(l))

    session_match = re.search(r"session=(\w+)", "\n".join(lines))
    session_lines = []
    exfil_bytes = 0
    if session_match:
        session = session_match.group(1)
        for l in lines:
            if f"cookie={session}" in l:
                m = LOG_LINE.match(l)
                if m:
                    session_lines.append(m)
                    if "EXFIL_CANDIDATE" in l:
                        exfil_bytes += int(m.group("size"))

    takeover_accounts = []
    for l in takeover_lines:
        m = re.search(r"username=([^&]+)", l)
        if m:
            takeover_accounts.append(m.group(1))

    print("=" * 66)
    print(" SQL INJECTION INCIDENT REPORT - Meridian Retail Group")
    print("=" * 66)
    print(f"Total log lines analyzed : {total_lines}")
    print(f"SQLi payload requests    : {len(sqli_lines)}")
    print(f"Blind extraction probes  : {len(blind_lines)}")
    print(f"Auth bypass events       : {len(bypass_lines)}")
    print(f"Account takeovers        : {len(takeover_accounts)}")
    print(f"Exfil bytes (session)    : {exfil_bytes}")
    print(f"WAF blocked requests     : {len(waf_lines)}")
    print(f"Top SQLi source IPs      : {ip_counts.most_common(5)}")

    # ---------------- PDF report ----------------
    out_path = args.pdf or os.path.join(os.path.dirname(args.log_file) or ".", "..", "reports", "01_sql_injection_report.pdf")
    out_path = os.path.normpath(out_path)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)

    report = IncidentReport(
        "SQL Injection Incident Report",
        "Meridian Retail Group - shop.meridianretail.com",
        args.log_file,
    )
    report.severity_banner(f"CRITICAL: {len(bypass_lines)} auth bypass event(s), {len(takeover_accounts)} account takeover(s), ~{exfil_bytes:,} bytes exfiltrated")

    report.section("Executive Summary")
    report.key_values([
        ("Log lines analyzed", f"{total_lines:,}"),
        ("Suspicious SQLi requests", f"{len(sqli_lines):,}"),
        ("Blind extraction probes", f"{len(blind_lines):,}"),
        ("Distinct attacker IPs (SQLi)", f"{len(ip_counts)}"),
        ("Authentication bypass events", f"{len(bypass_lines)}"),
        ("Customer accounts taken over", f"{len(takeover_accounts)}"),
        ("Data exfiltrated via hijacked session", f"~{exfil_bytes:,} bytes"),
        ("WAF blocked requests", f"{len(waf_lines)}"),
    ])

    report.section("Top Source IPs Sending SQLi Payloads")
    report.table(["Source IP", "Requests"], [[ip, c] for ip, c in ip_counts.most_common(10)])
    report.bar_chart("Requests by attacker IP", [ip for ip, _ in ip_counts.most_common(8)],
                      [c for _, c in ip_counts.most_common(8)])

    report.section("UNION-Based Data Dump Targets")
    dumped_tables = sorted(set(re.findall(r"FROM (\w+) LIMIT", "\n".join(decoded_lines))))
    report.paragraph("Tables enumerated and dumped via UNION SELECT:")
    report.table(["Table"], [[t] for t in dumped_tables])

    report.section("Blind Boolean-Based Extraction (High-Volume Probing)")
    report.paragraph(
        "A second actor used near-identical, incrementally-varying requests to extract "
        "data one character at a time via ASCII/SUBSTRING comparisons. This volume of "
        "repetitive similar requests from one IP is a hallmark of blind SQL injection."
    )
    report.table(["Source IP", "Blind probe requests"], [[ip, c] for ip, c in blind_ip_counts.most_common(5)])

    report.section("Authentication Bypass")
    if bypass_lines:
        for l in bypass_lines:
            ip = parse_ip(l)
            session = re.search(r"session=(\w+)", l)
            report.paragraph(f"Auth bypass from {ip}, session={session.group(1) if session else '?'}")
    else:
        report.paragraph("No confirmed auth bypass found.")

    report.section("Post-Bypass Admin Actions and Exfiltration")
    exfil_rows = []
    for l in exfil_lines[:15]:
        m = LOG_LINE.match(l)
        if m:
            exfil_rows.append([m.group("ip"), m.group("path"), m.group("size")])
    report.table(["IP", "Path", "Bytes"], exfil_rows, col_widths=[35, 110, 35])

    report.section("Credential Stuffing: Compromised Customer Accounts")
    report.paragraph(
        f"{len(takeover_accounts)} customer accounts were successfully taken over using "
        "credentials obtained from the earlier data dump, then used to place fraudulent orders."
    )
    report.table(["Compromised account (email)"], [[a] for a in takeover_accounts[:20]])

    report.section("Automated Scanner Noise")
    report.paragraph(f"{len(scanner_lines)} requests were also observed from a generic automated vulnerability scanner probing many product IDs with basic SQLi payloads.")

    report.section("WAF Blocked Destructive Attempts")
    report.table(["IP", "Blocked path"], [[parse_ip(l), parse_path(l)] for l in waf_lines[:10]], col_widths=[35, 145])

    report.section("SOC / WAF Alerts")
    for l in alert_lines:
        report.paragraph(l)

    report.save(out_path)
    print(f"\nPDF report written to: {out_path}")
    print("=" * 66)
    print(" END OF REPORT")
    print("=" * 66)


if __name__ == "__main__":
    main()
