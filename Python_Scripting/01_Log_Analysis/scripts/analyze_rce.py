#!/usr/bin/env python3
"""
analyze_rce.py
Target: logs/02_rce_vantage_cloud_systems.log (Vantage Cloud Systems)

Detects reconnaissance, JNDI/Log4Shell style injection, malicious file
upload, webshell command execution, server takeover actions, internal
network sweeps, and outbound C2 beaconing across two independently
compromised hosts, mixed with ordinary portal traffic.

Usage: python analyze_rce.py <path-to-log> [--pdf output.pdf]

Missing packages (fpdf2) are installed automatically on first run.
"""

import argparse
import os
import sys
import re
from collections import Counter
from urllib.parse import unquote_plus

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
for _candidate_dir in (_SCRIPT_DIR, os.path.join(_SCRIPT_DIR, "..", "scripts"), os.path.join(_SCRIPT_DIR, "scripts")):
    if os.path.isfile(os.path.join(_candidate_dir, "pdf_report_lib.py")) and _candidate_dir not in sys.path:
        sys.path.insert(0, _candidate_dir)

try:
    from pdf_report_lib import IncidentReport
except ModuleNotFoundError:
    sys.exit(
        "pdf_report_lib.py not found (checked next to this script, ../scripts/, and ./scripts/).\n"
        "This script was likely copied out of its scripts/ folder without its sibling pdf_report_lib.py.\n"
        "Fix: run it from its original scripts/ directory, or copy pdf_report_lib.py alongside it."
    )

RECON_PATTERN = re.compile(r"actuator|jndi:|manager/html|\.git/config|console/", re.IGNORECASE)
LOG_LINE = re.compile(
    r'^(?P<ip>[\d.]+) - - \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\w+) (?P<path>\S+) (?P<proto>[^"]+)" '
    r'(?P<status>\d+) (?P<size>\d+) "(?P<referer>[^"]*)" "(?P<ua>[^"]*)"'
)


def load_lines(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        return [line.rstrip("\n") for line in f]


def _resolve_log_path(path):
    """Accepts a bare filename regardless of the caller's cwd: if it doesn't
    resolve as given (absolute or relative to the current directory), look
    for it next to this script's own logs/ and log_samples/ folders."""
    if os.path.isfile(path):
        return path
    script_dir = os.path.dirname(os.path.abspath(__file__))
    for sub in ("logs", "log_samples"):
        candidate = os.path.join(script_dir, "..", sub, os.path.basename(path))
        if os.path.isfile(candidate):
            return candidate
    return path


def extract_cmd(path):
    m = re.search(r"cmd=([^&\s]+)", path)
    return unquote_plus(m.group(1)) if m else ""


def parse_ip(line):
    m = LOG_LINE.match(line)
    return m.group("ip") if m else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("log_file", nargs="?", default="../logs/02_rce_vantage_cloud_systems.log")
    ap.add_argument("--pdf", default=None)
    args = ap.parse_args()
    args.log_file = _resolve_log_path(args.log_file)

    lines = load_lines(args.log_file)
    total_lines = len(lines)

    recon_lines = [l for l in lines if RECON_PATTERN.search(l)]
    jndi_hits = Counter(re.findall(r"\$\{jndi:[a-z]+://[^}]+\}", "\n".join(lines)))
    upload_lines = [l for l in lines if "documents/upload" in l and "filename=" in l]
    webshell_lines = [l for l in lines if "WEBSHELL_EXEC" in l]
    takeover_lines = [l for l in lines if "SERVER_TAKEOVER" in l]
    internal_scan_lines = [l for l in lines if "internal_scan" in l]
    beacon_lines = [l for l in lines if "FIREWALL_LOG" in l]
    hunter_lines = [l for l in lines if "webshell-hunter" in l]
    alert_lines = [l for l in lines if "SECURITY_ALERT" in l]

    attacker_ips = set()
    for l in lines:
        if "WEBSHELL_EXEC" in l or "SERVER_TAKEOVER" in l or "jndi:" in l:
            ip = parse_ip(l)
            if ip:
                attacker_ips.add(ip)

    compromised_hosts = sorted(set(re.findall(r"compromised host ([\w-]+)", "\n".join(beacon_lines))))
    beacon_dest_counts = Counter(re.findall(r"dst=([\d.]+) dport=(\d+)", "\n".join(beacon_lines)))

    print("=" * 66)
    print(" REMOTE CODE EXECUTION INCIDENT REPORT - Vantage Cloud Systems")
    print("=" * 66)
    print(f"Total log lines analyzed  : {total_lines}")
    print(f"Recon/probing requests    : {len(recon_lines)}")
    print(f"Webshell command execs    : {len(webshell_lines)}")
    print(f"Server takeover actions   : {len(takeover_lines)}")
    print(f"Internal network sweep    : {len(internal_scan_lines)}")
    print(f"C2 beacon events          : {len(beacon_lines)}")
    print(f"Compromised hosts         : {compromised_hosts}")
    print(f"Distinct attacker IPs     : {sorted(attacker_ips)}")

    out_path = args.pdf or os.path.normpath(os.path.join(os.path.dirname(args.log_file) or ".", "..", "reports", "02_rce_report.pdf"))
    os.makedirs(os.path.dirname(out_path), exist_ok=True)

    report = IncidentReport(
        "Remote Code Execution Incident Report",
        "Vantage Cloud Systems - portal.vantagecloud.io",
        args.log_file,
    )
    report.severity_banner(f"CRITICAL: {len(compromised_hosts)} host(s) fully compromised, {len(webshell_lines)} webshell commands executed, active C2 beaconing detected")

    report.section("Executive Summary")
    report.key_values([
        ("Log lines analyzed", f"{total_lines:,}"),
        ("Recon / probing requests", f"{len(recon_lines):,}"),
        ("JNDI/Log4Shell attempts", f"{sum(jndi_hits.values())}"),
        ("Malicious file uploads", f"{len(upload_lines)}"),
        ("Webshell commands executed", f"{len(webshell_lines):,}"),
        ("Server takeover actions", f"{len(takeover_lines)}"),
        ("Internal network sweep requests", f"{len(internal_scan_lines):,}"),
        ("Compromised hosts", ", ".join(compromised_hosts) if compromised_hosts else "none identified"),
        ("C2 beacon events observed", f"{len(beacon_lines):,}"),
    ])

    report.section("Reconnaissance and Vulnerability Probing")
    recon_rows = []
    for l in recon_lines[:15]:
        m = LOG_LINE.match(l)
        if m:
            recon_rows.append([m.group("ip"), m.group("path")])
    report.table(["IP", "Path"], recon_rows, col_widths=[45, 135])

    report.section("JNDI / Log4Shell Style Injection Attempts")
    report.table(["Payload", "Count"], [[p, c] for p, c in jndi_hits.items()])

    report.section("Malicious File Upload")
    upload_rows = []
    for l in upload_lines:
        m = re.search(r"filename=(\S+)", l)
        ip = parse_ip(l)
        if m:
            upload_rows.append([ip, m.group(1)])
    report.table(["IP", "Uploaded filename"], upload_rows)

    report.section("Webshell Command Execution Timeline (sample)")
    cmd_rows = []
    for l in webshell_lines:
        if "internal_scan" in l:
            continue
        m = LOG_LINE.match(l)
        if m:
            cmd_rows.append([m.group("time"), m.group("ip"), extract_cmd(m.group("path"))])
    report.table(["Time", "Attacker IP", "Command"], cmd_rows, col_widths=[45, 35, 100], max_rows=30)

    report.section("Server Takeover Indicators")
    report.paragraph(f"{len(takeover_lines)} commands were tagged SERVER_TAKEOVER (new privileged user, sudoers edit, cryptominer download, persistence via cron).")
    takeover_rows = []
    for l in takeover_lines:
        m = LOG_LINE.match(l)
        if m:
            takeover_rows.append([m.group("ip"), extract_cmd(m.group("path"))])
    report.table(["IP", "Command"], takeover_rows, col_widths=[45, 135])

    report.section("Internal Network Lateral Movement")
    report.paragraph(f"The webshell was used to sweep {len(internal_scan_lines)} internal hosts on port 22, indicating an attempt to move laterally beyond the compromised web server.")

    report.section("Outbound Command-and-Control Beaconing")
    report.bar_chart(
        "Beacon events by destination",
        [f"{dst}:{port}" for (dst, port), _ in beacon_dest_counts.most_common(8)],
        [c for _, c in beacon_dest_counts.most_common(8)],
    )

    report.section("Webshell-Hunting Bot (Third-Party Backdoor Discovery Attempts)")
    report.paragraph(f"{len(hunter_lines)} requests probed for common pre-existing webshell filenames left by other actors. All returned 404 in this incident.")

    report.section("SOC / EDR Detection and Containment")
    for l in alert_lines:
        report.paragraph(l)

    report.save(out_path)
    print(f"\nPDF report written to: {out_path}")
    print("=" * 66)
    print(" END OF REPORT")
    print("=" * 66)


if __name__ == "__main__":
    main()
