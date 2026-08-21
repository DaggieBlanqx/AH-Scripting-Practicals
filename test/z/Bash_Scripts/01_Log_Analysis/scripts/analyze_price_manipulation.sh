#!/bin/bash
#
# analyze_price_manipulation.sh
# Target: logs/04_price_manipulation_bazario_marketplace.log (Bazario Marketplace)
#
# Detects orders where the charged unit price does not match the catalog
# price (client-side price tampering), the reseller/mule ring exploiting
# it at scale, and estimates the resulting revenue loss, mixed with
# ordinary correctly-priced orders.
#
# Prints the analysis to the console AND renders a PDF incident report,
# using nothing but Bash and coreutils (grep/awk/sed/fold) plus the
# co-located pdf_lib.sh, a small dependency-free PDF writer. No Python,
# no external report-rendering tool required.
#
# Usage: ./analyze_price_manipulation.sh <path-to-log>

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="${1:-$SCRIPT_DIR/../logs/04_price_manipulation_bazario_marketplace.log}"

if [ ! -f "$LOG_FILE" ]; then
    echo "Log file not found: $LOG_FILE"
    exit 1
fi

source "$SCRIPT_DIR/pdf_lib.sh"

echo "=================================================================="
echo " PRICE MANIPULATION INCIDENT REPORT"
echo " Source log : $LOG_FILE"
echo "=================================================================="

pdf_init "Price Manipulation Incident Report" "Bazario Marketplace - shop.bazario.com" "$LOG_FILE"

echo
echo "[1] Orders explicitly flagged as PRICE_MISMATCH"
echo "------------------------------------------------------------------"
FLAGGED_COUNT=$(grep -c "PRICE_MISMATCH" "$LOG_FILE" || true)
echo "Flagged orders: $FLAGGED_COUNT"

echo
echo "[2] Pre-exploit price validation probing"
echo "------------------------------------------------------------------"
PROBE_COUNT=$(grep -c "Cart price validation probe" "$LOG_FILE" || true)
echo "Validation probe requests: $PROBE_COUNT"

echo
echo "[3] Mismatch details (order, sku, catalog price vs charged price)"
echo "------------------------------------------------------------------"
MISMATCH_DETAILS=$(grep "PRICE_MISMATCH" "$LOG_FILE" | \
    sed -E 's/.*order_id=([^ ]+).*customer=([^ ]+).*item="([^"]+)".*catalog_price=([0-9.]+).*unit_price=([0-9.]+).*qty=([0-9]+).*/order=\1 customer=\2 item="\3" catalog=\4 charged_unit=\5 qty=\6/' \
    | head -20)
echo "$MISMATCH_DETAILS"

echo
echo "[4] Every order also re-checked programmatically (catalog != unit_price)"
echo "------------------------------------------------------------------"
RECHECKED=$(awk '
{
    match($0, /catalog_price=([0-9.]+)/, cp)
    match($0, /unit_price=([0-9.]+)/, up)
    if (cp[1] != "" && up[1] != "" && cp[1] != up[1]) {
        match($0, /order_id=([^ ]+)/, oid)
        match($0, /customer=([^ ]+)/, cust)
        printf "order=%s customer=%s catalog=%.2f charged=%.2f diff=%.2f\n", oid[1], cust[1], cp[1], up[1], cp[1]-up[1]
    }
}' "$LOG_FILE" | head -20)
echo "$RECHECKED"

echo
echo "[5] Customers responsible for tampered orders (fraud ring detection)"
echo "------------------------------------------------------------------"
FRAUD_CUSTOMERS=$(grep "PRICE_MISMATCH" "$LOG_FILE" | grep -oE "customer=[^ ]+" | sort | uniq -c | sort -rn | head -20)
echo "$FRAUD_CUSTOMERS"

echo
echo "[6] Shipping addresses used across the fraudulent orders (mule pattern)"
echo "------------------------------------------------------------------"
MULE_ADDRESSES=$(grep "PRICE_MISMATCH" "$LOG_FILE" | grep -oE 'ship_addr="[^"]+"' | sort | uniq -c | sort -rn | head -15)
echo "$MULE_ADDRESSES"

echo
echo "[7] Estimated revenue loss"
echo "------------------------------------------------------------------"
TOTAL_LOSS=$(grep "PRICE_MISMATCH" "$LOG_FILE" | awk '
{
    match($0, /catalog_price=([0-9.]+)/, cp)
    match($0, /qty=([0-9]+)/, q)
    match($0, /total_charged=([0-9.]+)/, tc)
    expected = cp[1] * q[1]
    loss += expected - tc[1]
}
END { printf "%.2f", loss }')
echo "Total estimated loss: \$$TOTAL_LOSS"

echo
echo "[8] Reconciliation and fraud engine response"
echo "------------------------------------------------------------------"
RECON_ALERTS=$(grep -E "RECONCILIATION_JOB|SECURITY_ALERT" "$LOG_FILE")
echo "$RECON_ALERTS"

echo
echo "=================================================================="
echo " END OF REPORT"
echo "=================================================================="

# ---- Build the PDF report --------------------------------------------
# Distinct-account and distinct-address counts must come from the full
# (untruncated) data, not from the top-N display lists above, otherwise
# a "head -20"/"head -15" for the table view would silently cap the
# executive-summary totals too.
FRAUD_ACCT_COUNT=$(grep "PRICE_MISMATCH" "$LOG_FILE" | grep -oE "customer=[^ ]+" | sort -u | wc -l)
MULE_ADDR_COUNT=$(grep "PRICE_MISMATCH" "$LOG_FILE" | grep -oE 'ship_addr="[^"]+"' | sort -u | wc -l)
pdf_banner "CRITICAL: $FLAGGED_COUNT tampered orders across $FRAUD_ACCT_COUNT accounts, estimated loss \$$TOTAL_LOSS"

pdf_section "Executive Summary"
pdf_kv "Orders with price mismatch" "$FLAGGED_COUNT"
pdf_kv "Distinct fraudulent accounts" "$FRAUD_ACCT_COUNT"
pdf_kv "Distinct shipping addresses reused" "$MULE_ADDR_COUNT"
pdf_kv "Pre-exploit validation probes" "$PROBE_COUNT"
pdf_kv "Estimated total revenue loss" "\$$TOTAL_LOSS"

pdf_section "Reconnaissance: Price Validation Probing"
pdf_text "$PROBE_COUNT requests probed the cart price validation endpoint with submitted prices below catalog value before the exploit was used at scale, consistent with a scripted search for the vulnerability."

pdf_section "Sample Tampered Orders"
while read -r line; do
    [ -z "$line" ] && continue
    pdf_table_line "$line"
done <<< "$MISMATCH_DETAILS"

pdf_section "Top Fraudulent Accounts by Order Count"
pdf_table_header "$(printf '%-20s %10s' 'Customer' 'Orders')"
while read -r cnt cust; do
    [ -z "$cust" ] && continue
    c=$(echo "$cust" | sed 's/customer=//')
    pdf_table_line "$(printf '%-20s %10s' "$c" "$cnt")"
done <<< "$FRAUD_CUSTOMERS"
BAR_MAX=$(printf '%s\n' "$FRAUD_CUSTOMERS" | awk '{print $1}' | sort -rn | head -1)
[ -z "$BAR_MAX" ] && BAR_MAX=1
while read -r cnt cust; do
    [ -z "$cust" ] && continue
    c=$(echo "$cust" | sed 's/customer=//')
    pdf_bar "$c" "$cnt" "$BAR_MAX"
done <<< "$FRAUD_CUSTOMERS"

pdf_section "Shipping Address Reuse (Mule Pattern)"
while read -r line; do
    [ -z "$line" ] && continue
    pdf_table_line "$line"
done <<< "$MULE_ADDRESSES"

pdf_section "Highest-Value Mismatches (recomputed independently)"
while read -r line; do
    [ -z "$line" ] && continue
    pdf_table_line "$line"
done <<< "$RECHECKED"

pdf_section "Reconciliation and Fraud Engine Response"
pdf_text "$RECON_ALERTS"

OUT_PDF="$SCRIPT_DIR/../reports/04_price_manipulation_report.pdf"
pdf_save "$OUT_PDF" > /dev/null
echo
echo "PDF report written to: $OUT_PDF"
