#!/bin/bash
#
# analyze_privilege_escalation.sh
# Target: logs/03_privilege_escalation_kestrel_manufacturing.log (Kestrel Manufacturing Corp)
#
# Detects a bulk automated IDOR sweep against a broken self-role-change API
# (using a leaked internal token dump), the accounts it successfully
# escalated to admin, the subset abused for payroll fraud and rogue admin
# account creation, and the incident response, mixed with ordinary HR/ERP
# audit activity.
#
# Prints the analysis to the console AND renders a PDF incident report,
# using nothing but Bash and coreutils (grep/awk/sed/fold) plus the
# co-located pdf_lib.sh, a small dependency-free PDF writer. No Python,
# no external report-rendering tool required.
#
# Usage: ./analyze_privilege_escalation.sh <path-to-log>

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="${1:-$SCRIPT_DIR/../logs/03_privilege_escalation_kestrel_manufacturing.log}"

if [ ! -f "$LOG_FILE" ]; then
    echo "Log file not found: $LOG_FILE"
    exit 1
fi

source "$SCRIPT_DIR/pdf_lib.sh"

echo "=================================================================="
echo " VERTICAL PRIVILEGE ESCALATION INCIDENT REPORT"
echo " Source log : $LOG_FILE"
echo "=================================================================="

pdf_init "Vertical Privilege Escalation Incident Report" "Kestrel Manufacturing Corp - erp.kestrelmfg.local" "$LOG_FILE"

echo
echo "[1] Bulk automated IDOR sweep against /api/users/self/role"
echo "------------------------------------------------------------------"
ATTEMPTS=$(grep -c "/api/users/self/role" "$LOG_FILE" || true)
echo "Total attempts: $ATTEMPTS"

echo
echo "[2] Self-service role change events (should never succeed)"
echo "------------------------------------------------------------------"
SUCCESS=$(grep "ROLE_CHANGED" "$LOG_FILE" | grep -c "changed_by=SELF" || true)
echo "Successful self-escalations: $SUCCESS"
ESCALATIONS=$(grep "ROLE_CHANGED" "$LOG_FILE" | grep "changed_by=SELF" | head -20)
echo "$ESCALATIONS"

echo
echo "[3] Denied access attempts prior to escalation (recon on admin area)"
echo "------------------------------------------------------------------"
DENIED_RECON=$(awk -F'|' '/ACCESS_ATTEMPT/ && /DENIED_403/ {print}' "$LOG_FILE" | sed 's/^ *//')
echo "$DENIED_RECON"

echo
echo "[4] New admin accounts created and by whom"
echo "------------------------------------------------------------------"
ROGUE_USERS=$(grep "CREATE_USER" "$LOG_FILE" | grep "new_role=admin" \
    | sed -E 's/.*user=([^ |]+).*new_user=([^ |]+).*/creator=\1 -> new_admin=\2/')
echo "$ROGUE_USERS"

echo
echo "[5] Finance portal access granted to non-finance accounts"
echo "------------------------------------------------------------------"
FINANCE_ACCESS=$(grep -E "target=/finance/" "$LOG_FILE" \
    | sed -E 's/^([0-9-]+ [0-9:]+) .*user=([^ |]+).*target=([^ |]+).*/\1 user=\2 target=\3/' | head -25)
echo "$FINANCE_ACCESS"

echo
echo "[6] Payroll anomalies (fraudulent or self-modified records)"
echo "------------------------------------------------------------------"
PAYROLL_ANOMALIES=$(grep -E "ANOMALY_DUPLICATE_IDENTITY|ANOMALY_SELF_MODIFY" "$LOG_FILE" | head -20)
echo "$PAYROLL_ANOMALIES"

echo
echo "[7] Attempt to cover tracks by deleting audit history"
echo "------------------------------------------------------------------"
COVER_UP=$(grep "DELETE_AUDIT_LOG" "$LOG_FILE" || echo "No audit-log deletion attempt found.")
echo "$COVER_UP"

echo
echo "[8] Users whose role changed from STANDARD to admin (summary count)"
echo "------------------------------------------------------------------"
ESCALATION_COUNT=$(grep -oE "user=[^ |]+ \| dept=[^ |]+ \| role=admin \| action=ROLE_CHANGED" "$LOG_FILE" | wc -l)
echo "Privilege escalation events: $ESCALATION_COUNT"

echo
echo "[9] Incident response actions taken"
echo "------------------------------------------------------------------"
RESPONSE=$(grep -E "SECURITY_ALERT|DISABLE_USER" "$LOG_FILE" | head -25)
echo "$RESPONSE"

echo
echo "=================================================================="
echo " END OF REPORT"
echo "=================================================================="

# ---- Build the PDF report --------------------------------------------
ROGUE_COUNT=$(printf '%s\n' "$ROGUE_USERS" | grep -c .)
ANOMALY_COUNT=$(printf '%s\n' "$PAYROLL_ANOMALIES" | grep -c .)
SUCCESS_RATE="0.0"
if [ "$ATTEMPTS" -gt 0 ]; then
    SUCCESS_RATE=$(awk -v s="$SUCCESS" -v a="$ATTEMPTS" 'BEGIN{printf "%.1f", (s/a)*100}')
fi

pdf_banner "CRITICAL: $SUCCESS accounts self-escalated to admin, $ROGUE_COUNT rogue admin accounts created, $ANOMALY_COUNT payroll records tampered"

pdf_section "Executive Summary"
pdf_kv "Bulk IDOR attempts against self/role API" "$ATTEMPTS"
pdf_kv "Successful self-escalations" "$SUCCESS ($SUCCESS_RATE% of attempts)"
pdf_kv "Denied admin-area recon probes" "$(printf '%s\n' "$DENIED_RECON" | grep -c .)"
pdf_kv "Rogue admin accounts created" "$ROGUE_COUNT"
pdf_kv "Unauthorized finance portal accesses" "$(printf '%s\n' "$FINANCE_ACCESS" | grep -c .)"
pdf_kv "Payroll fraud anomalies" "$ANOMALY_COUNT"
pdf_kv "Audit-log deletion attempts (blocked)" "$(printf '%s\n' "$COVER_UP" | grep -c "DELETE_AUDIT_LOG")"
pdf_kv "Accounts disabled by incident response" "$(grep -c "DISABLE_USER" "$LOG_FILE" || echo 0)"

pdf_section "Bulk Automated IDOR Sweep"
pdf_text "A leaked internal API token dump was used to script the broken self-role-change endpoint against every employee account. Most tokens were stale and denied, but a meaningful fraction were still valid, each producing an immediate role escalation."
pdf_kv "Total attempts" "$ATTEMPTS"
pdf_kv "Succeeded" "$SUCCESS"

pdf_section "Accounts Successfully Escalated to Admin (sample)"
while read -r line; do
    [ -z "$line" ] && continue
    pdf_table_line "$line"
done <<< "$ESCALATIONS"

pdf_section "Denied Reconnaissance on Admin Area (pre-escalation probing)"
while read -r line; do
    [ -z "$line" ] && continue
    pdf_table_line "$line"
done <<< "$DENIED_RECON"

pdf_section "Rogue Admin Accounts Created"
while read -r line; do
    [ -z "$line" ] && continue
    pdf_table_line "$line"
done <<< "$ROGUE_USERS"

pdf_section "Unauthorized Finance Portal Access (sample)"
while read -r line; do
    [ -z "$line" ] && continue
    pdf_table_line "$line"
done <<< "$FINANCE_ACCESS"

pdf_section "Payroll Fraud Anomalies (sample)"
while read -r line; do
    [ -z "$line" ] && continue
    pdf_table_line "$line"
done <<< "$PAYROLL_ANOMALIES"

pdf_section "Cover-Up Attempt"
pdf_text "$COVER_UP"

pdf_section "Incident Response"
while read -r line; do
    [ -z "$line" ] && continue
    pdf_table_line "$line"
done <<< "$RESPONSE"

OUT_PDF="$SCRIPT_DIR/../reports/03_privilege_escalation_report.pdf"
pdf_save "$OUT_PDF" > /dev/null
echo
echo "PDF report written to: $OUT_PDF"
