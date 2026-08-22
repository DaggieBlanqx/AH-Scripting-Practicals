#!/usr/bin/env python3
"""
analyze_price_manipulation.py
Target: logs/04_price_manipulation_bazario_marketplace.log (Bazario Marketplace)

Detects orders where the charged unit price does not match the catalog
price (client-side price tampering), the reseller/mule ring exploiting it
at scale, the reconnaissance that preceded it, and estimates the resulting
revenue loss, mixed with ordinary correctly-priced orders.

Usage: python analyze_price_manipulation.py <path-to-log> [--pdf output.pdf]

Missing packages (fpdf2) are installed automatically on first run.
"""

import argparse
import os
import sys
import re
from collections import Counter

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

ORDER_FIELDS = re.compile(
    r"order_id=(?P<order_id>\S+) customer=(?P<customer>\S+)(?: email=(?P<email>\S+))?(?: phone=(?P<phone>\S+))? "
    r"sku=(?P<sku>\S+) "
    r'item="(?P<item>[^"]+)" catalog_price=(?P<catalog_price>[\d.]+) '
    r"unit_price=(?P<unit_price>[\d.]+) qty=(?P<qty>\d+) "
    r"total_charged=(?P<total_charged>[\d.]+)"
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("log_file", nargs="?", default="../logs/04_price_manipulation_bazario_marketplace.log")
    ap.add_argument("--pdf", default=None)
    args = ap.parse_args()
    args.log_file = _resolve_log_path(args.log_file)

    lines = load_lines(args.log_file)
    total_lines = len(lines)

    orders = []
    for l in lines:
        if "ORDER_LOG" not in l:
            continue
        m = ORDER_FIELDS.search(l)
        if not m:
            continue
        d = m.groupdict()
        d["catalog_price"] = float(d["catalog_price"])
        d["unit_price"] = float(d["unit_price"])
        d["qty"] = int(d["qty"])
        d["total_charged"] = float(d["total_charged"])
        d["flagged"] = "PRICE_MISMATCH" in l
        ship_match = re.search(r'ship_addr="([^"]+)"', l)
        d["ship_addr"] = ship_match.group(1) if ship_match else None
        orders.append(d)

    flagged = [o for o in orders if o["flagged"]]
    probe_lines = [l for l in lines if "Cart price validation probe" in l]
    reconciliation_lines = [l for l in lines if "RECONCILIATION_JOB" in l]
    alert_lines = [l for l in lines if "SECURITY_ALERT" in l]

    customer_counts = Counter(o["customer"] for o in flagged)
    addr_counts = Counter(o["ship_addr"] for o in flagged if o["ship_addr"])
    total_loss = sum(o["catalog_price"] * o["qty"] - o["total_charged"] for o in flagged)

    print("=" * 66)
    print(" PRICE MANIPULATION INCIDENT REPORT - Bazario Marketplace")
    print("=" * 66)
    print(f"Total log lines analyzed  : {total_lines}")
    print(f"Total orders parsed       : {len(orders)}")
    print(f"Orders flagged mismatched : {len(flagged)}")
    print(f"Distinct fraud accounts   : {len(customer_counts)}")
    print(f"Estimated revenue loss    : ${total_loss:,.2f}")
    print(f"Pre-exploit price probes  : {len(probe_lines)}")

    out_path = args.pdf or os.path.normpath(os.path.join(os.path.dirname(args.log_file) or ".", "..", "reports", "04_price_manipulation_report.pdf"))
    os.makedirs(os.path.dirname(out_path), exist_ok=True)

    report = IncidentReport(
        "Price Manipulation Incident Report",
        "Bazario Marketplace - shop.bazario.com",
        args.log_file,
    )
    report.severity_banner(f"CRITICAL: {len(flagged)} tampered orders across {len(customer_counts)} accounts, estimated loss ${total_loss:,.2f}")

    report.section("Executive Summary")
    report.key_values([
        ("Log lines analyzed", f"{total_lines:,}"),
        ("Total orders parsed", f"{len(orders):,}"),
        ("Orders with price mismatch", f"{len(flagged):,}"),
        ("Distinct fraudulent accounts", f"{len(customer_counts)}"),
        ("Distinct shipping addresses reused", f"{len(addr_counts)}"),
        ("Pre-exploit validation probes", f"{len(probe_lines)}"),
        ("Estimated total revenue loss", f"${total_loss:,.2f}"),
    ])

    report.section("Reconnaissance: Price Validation Probing")
    report.paragraph(
        f"{len(probe_lines)} requests probed the cart price validation endpoint with "
        "submitted prices below catalog value before the exploit was used at scale, "
        "consistent with a scripted search for the vulnerability."
    )

    report.section("Top Fraudulent Accounts by Order Count")
    report.table(["Customer", "Tampered orders"], [[c, n] for c, n in customer_counts.most_common(15)])
    report.bar_chart("Tampered orders by account", [c for c, _ in customer_counts.most_common(10)],
                      [n for _, n in customer_counts.most_common(10)])

    report.section("Shipping Address Reuse (Mule Pattern)")
    report.table(["Shipping address", "Orders"], [[a, n] for a, n in addr_counts.most_common(15)], col_widths=[140, 40])

    report.section("Highest-Value Mismatches")
    top_mismatches = sorted(flagged, key=lambda o: o["catalog_price"] * o["qty"] - o["total_charged"], reverse=True)[:15]
    rows = [[o["order_id"], o["customer"], o["item"], f"${o['catalog_price']:.2f}", f"${o['unit_price']:.2f}", o["qty"]] for o in top_mismatches]
    report.table(["Order", "Customer", "Item", "Catalog", "Charged", "Qty"], rows, col_widths=[28, 28, 70, 22, 22, 14])

    report.section("Reconciliation and Fraud Engine Response")
    for l in reconciliation_lines:
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
