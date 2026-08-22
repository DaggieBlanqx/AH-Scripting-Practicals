#!/usr/bin/env python3
"""
analyze_bruteforce.py
Target: logs/05_bruteforce_solstice_health_networks.log (Solstice Health Networks)

Classic SSH auth.log analysis: separates ordinary internet background
scanning noise from a focused credential-stuffing campaign against real
employee usernames, finds the successful compromise, and traces lateral
movement and data exfiltration, mixed with routine legitimate SSH activity.

Usage: python analyze_bruteforce.py <path-to-log> [--pdf output.pdf]

Missing packages (fpdf2) are installed automatically on first run.
"""

import argparse
import os
import sys
import re
from collections import Counter, defaultdict

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

FAILED_RE = re.compile(r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)")


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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("log_file", nargs="?", default="../logs/05_bruteforce_solstice_health_networks.log")
    ap.add_argument("--pdf", default=None)
    args = ap.parse_args()
    args.log_file = _resolve_log_path(args.log_file)

    lines = load_lines(args.log_file)
    total_lines = len(lines)

    legit_logins = [l for l in lines if "Accepted publickey" in l]
    failed = [FAILED_RE.search(l) for l in lines if "Failed password" in l]
    failed = [m for m in failed if m]

    ip_counts = Counter(m.group("ip") for m in failed)
    user_counts = Counter(m.group("user") for m in failed)

    valid_attempt_lines = [l for l in lines if "Failed password for " in l and "invalid user" not in l]
    ip_to_users = defaultdict(set)
    for l in valid_attempt_lines:
        m = FAILED_RE.search(l)
        if m:
            ip_to_users[m.group("ip")].add(m.group("user"))
    stuffing_ips = {ip: users for ip, users in ip_to_users.items() if len(users) > 1}

    success_lines = [l for l in lines if "Accepted password" in l]
    sudo_lines = [l for l in lines if "sudo:" in l]
    lateral_lines = [l for l in lines if "lateral movement" in l]
    exfil_lines = [l for l in lines if "scp[" in l or "outbound-fw" in l]
    ban_lines = [l for l in lines if "fail2ban" in l]
    alert_lines = [l for l in lines if "SECURITY_ALERT" in l]

    print("=" * 66)
    print(" BRUTE FORCE / CREDENTIAL STUFFING INCIDENT REPORT - Solstice Health Networks")
    print("=" * 66)
    print(f"Total log lines analyzed      : {total_lines}")
    print(f"Legitimate successful logins  : {len(legit_logins)}")
    print(f"Failed login attempts         : {len(failed)}")
    print(f"Credential-stuffing IPs       : {len(stuffing_ips)}")
    print(f"Successful compromises        : {len(success_lines)}")

    out_path = args.pdf or os.path.normpath(os.path.join(os.path.dirname(args.log_file) or ".", "..", "reports", "05_bruteforce_report.pdf"))
    os.makedirs(os.path.dirname(out_path), exist_ok=True)

    report = IncidentReport(
        "Brute Force / Credential Stuffing Incident Report",
        "Solstice Health Networks - vpn.solsticehealth.org",
        args.log_file,
    )
    report.severity_banner(f"CRITICAL: {len(success_lines)} account(s) compromised, lateral movement to {len(lateral_lines)} internal host(s), data exfiltration detected")

    report.section("Executive Summary")
    report.key_values([
        ("Log lines analyzed", f"{total_lines:,}"),
        ("Legitimate successful logins (publickey)", f"{len(legit_logins):,}"),
        ("Total failed login attempts", f"{len(failed):,}"),
        ("Distinct source IPs (failed logins)", f"{len(ip_counts)}"),
        ("IPs showing credential-stuffing pattern", f"{len(stuffing_ips)}"),
        ("Successful compromises", f"{len(success_lines)}"),
        ("Lateral movement events", f"{len(lateral_lines)}"),
        ("Data exfiltration events", f"{len(exfil_lines)}"),
        ("IPs banned in response", f"{len(ban_lines)}"),
    ])

    report.section("Top Source IPs by Failed Login Count")
    report.table(["Source IP", "Failed attempts"], ip_counts.most_common(10))
    report.bar_chart("Failed logins by source IP", [ip for ip, _ in ip_counts.most_common(8)],
                      [c for _, c in ip_counts.most_common(8)])

    report.section("Most-Targeted Usernames")
    report.table(["Username", "Failed attempts"], user_counts.most_common(15))

    report.section("Credential Stuffing Detection")
    report.paragraph(
        "Ordinary internet scanners repeatedly hammer a single default username. "
        "A source IP that fails password checks against several different real "
        "usernames is a much stronger credential-stuffing signal than raw failure volume."
    )
    stuffing_rows = sorted(((ip, len(u)) for ip, u in stuffing_ips.items()), key=lambda x: -x[1])
    report.table(["Source IP", "Distinct usernames targeted"], stuffing_rows)

    report.section("Successful Compromise")
    for l in success_lines:
        report.paragraph(l)

    report.section("Post-Compromise Privileged Commands (sudo trail)")
    sudo_rows = []
    for l in sudo_lines:
        m = re.match(r"^(\w+ \d+ [\d:]+).*sudo: (.*)$", l)
        if m:
            sudo_rows.append([m.group(1), m.group(2)])
    report.table(["Time", "Command"], sudo_rows, col_widths=[40, 140])

    report.section("Lateral Movement")
    for l in lateral_lines:
        m = re.search(r"target: ([^)]+)\)", l)
        if m:
            report.paragraph(m.group(1))

    report.section("Data Exfiltration")
    for l in exfil_lines:
        report.paragraph(l)

    report.section("Response: Bans and SOC Alert")
    for l in ban_lines:
        report.paragraph(l)
    for l in alert_lines:
        report.paragraph(l)

    report.save(out_path)
    print(f"\nPDF report written to: {out_path}")
    print("=" * 66)
    print(" END OF REPORT")
    print("=" * 66)


if __name__ == "__main__":
    main()
