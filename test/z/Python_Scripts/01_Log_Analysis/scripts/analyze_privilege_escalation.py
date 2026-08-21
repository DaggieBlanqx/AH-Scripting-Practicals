#!/usr/bin/env python3
"""
analyze_privilege_escalation.py
Target: logs/03_privilege_escalation_kestrel_manufacturing.log (Kestrel Manufacturing Corp)

Detects a bulk automated IDOR sweep against a broken self-role-change API
(using a leaked internal token dump), the accounts it successfully
escalated to admin, the subset abused for payroll fraud and rogue admin
account creation, and the incident response, mixed with ordinary HR/ERP
audit activity.

Usage: python analyze_privilege_escalation.py <path-to-log> [--pdf output.pdf]

Missing packages (fpdf2) are installed automatically on first run.
"""

import argparse
import os
import re
from collections import Counter

from pdf_report_lib import IncidentReport


def load_lines(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        return [line.rstrip("\n") for line in f]


def field(line, name):
    m = re.search(rf"{name}=([^|]+)", line)
    return m.group(1).strip() if m else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("log_file", nargs="?", default="../logs/03_privilege_escalation_kestrel_manufacturing.log")
    ap.add_argument("--pdf", default=None)
    args = ap.parse_args()

    lines = load_lines(args.log_file)
    total_lines = len(lines)

    idor_attempts = [l for l in lines if "API_CALL" in l and "/api/users/self/role" in l]
    role_changes = [l for l in lines if "ROLE_CHANGED" in l and "changed_by=SELF" in l]
    denied_recon = [l for l in lines if "ACCESS_ATTEMPT" in l and "DENIED_403" in l]
    rogue_users = [l for l in lines if "CREATE_USER" in l and "new_role=admin" in l]
    finance_access = [l for l in lines if "target=/finance/" in l]
    payroll_anomalies = [l for l in lines if "ANOMALY_DUPLICATE_IDENTITY" in l or "ANOMALY_SELF_MODIFY" in l]
    cover_up = [l for l in lines if "DELETE_AUDIT_LOG" in l]
    alerts = [l for l in lines if "SECURITY_ALERT" in l]
    disables = [l for l in lines if "DISABLE_USER" in l]

    escalated_users = sorted(set(field(l, "user") for l in role_changes if field(l, "user")))
    denied_attempts = len(idor_attempts) - len(role_changes)

    print("=" * 66)
    print(" VERTICAL PRIVILEGE ESCALATION INCIDENT REPORT - Kestrel Manufacturing Corp")
    print("=" * 66)
    print(f"Total log lines analyzed        : {total_lines}")
    print(f"Bulk IDOR attempts (bulk sweep)  : {len(idor_attempts)}")
    print(f"Accounts successfully escalated  : {len(role_changes)}")
    print(f"Rogue admin accounts created     : {len(rogue_users)}")
    print(f"Payroll fraud anomalies          : {len(payroll_anomalies)}")
    print(f"Accounts disabled in response    : {len(disables)}")

    out_path = args.pdf or os.path.normpath(os.path.join(os.path.dirname(args.log_file) or ".", "..", "reports", "03_privilege_escalation_report.pdf"))
    os.makedirs(os.path.dirname(out_path), exist_ok=True)

    report = IncidentReport(
        "Vertical Privilege Escalation Incident Report",
        "Kestrel Manufacturing Corp - erp.kestrelmfg.local",
        args.log_file,
    )
    report.severity_banner(f"CRITICAL: {len(role_changes)} accounts self-escalated to admin, {len(rogue_users)} rogue admin accounts created, {len(payroll_anomalies)} payroll records tampered")

    report.section("Executive Summary")
    success_rate = (len(role_changes) / len(idor_attempts) * 100) if idor_attempts else 0
    report.key_values([
        ("Log lines analyzed", f"{total_lines:,}"),
        ("Bulk IDOR attempts against /api/users/self/role", f"{len(idor_attempts):,}"),
        ("Successful self-escalations", f"{len(role_changes)} ({success_rate:.1f}% of attempts)"),
        ("Denied admin-area recon probes", f"{len(denied_recon)}"),
        ("Rogue admin accounts created", f"{len(rogue_users)}"),
        ("Unauthorized finance portal accesses", f"{len(finance_access)}"),
        ("Payroll fraud anomalies", f"{len(payroll_anomalies)}"),
        ("Audit-log deletion attempts (blocked)", f"{len(cover_up)}"),
        ("Accounts disabled by incident response", f"{len(disables)}"),
    ])

    report.section("Bulk Automated IDOR Sweep")
    report.paragraph(
        "A leaked internal API token dump was used to script the broken "
        "self-role-change endpoint against every employee account. Most tokens "
        "were stale and denied, but a meaningful fraction were still valid, "
        "each producing an immediate role escalation."
    )
    report.key_values([
        ("Total attempts", f"{len(idor_attempts)}"),
        ("Denied (stale token)", f"{denied_attempts}"),
        ("Succeeded", f"{len(role_changes)}"),
    ])

    report.section("Accounts Successfully Escalated to Admin")
    report.table(["Escalated account"], [[u] for u in escalated_users], max_rows=40)

    report.section("Denied Reconnaissance on Admin Area (pre-escalation probing)")
    recon_rows = []
    for l in denied_recon[:15]:
        recon_rows.append([field(l, "user"), field(l, "target")])
    report.table(["User", "Target"], recon_rows)

    report.section("Rogue Admin Accounts Created")
    rogue_rows = []
    for l in rogue_users:
        rogue_rows.append([field(l, "user"), field(l, "new_user")])
    report.table(["Created by", "New admin account"], rogue_rows)

    report.section("Unauthorized Finance Portal Access")
    finance_rows = []
    for l in finance_access[:20]:
        ts = l.split(" | ")[0].strip()
        finance_rows.append([ts, field(l, "user"), field(l, "target")])
    report.table(["Time", "User", "Target"], finance_rows, col_widths=[45, 55, 80])

    report.section("Payroll Fraud Anomalies")
    for l in payroll_anomalies[:15]:
        report.paragraph(l.split(" | ", 1)[1] if " | " in l else l)

    report.section("Cover-Up Attempt")
    if cover_up:
        for l in cover_up:
            report.paragraph(l)
    else:
        report.paragraph("No audit-log deletion attempt found.")

    report.section("Incident Response")
    for l in alerts:
        report.paragraph(l)
    report.table(["Disabled account"], [[field(l, "target")] for l in disables[:30]])

    report.save(out_path)
    print(f"\nPDF report written to: {out_path}")
    print("=" * 66)
    print(" END OF REPORT")
    print("=" * 66)


if __name__ == "__main__":
    main()
