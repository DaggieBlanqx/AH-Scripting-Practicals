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

# Accept a bare filename regardless of the caller's cwd: if it doesn't
# resolve as given (absolute or relative to the current directory), look
# for it next to this script's own logs/ and log_samples/ folders.
if [ ! -f "$LOG_FILE" ]; then
    for _candidate in "$SCRIPT_DIR/../logs/$(basename "$LOG_FILE")" "$SCRIPT_DIR/../log_samples/$(basename "$LOG_FILE")"; do
        if [ -f "$_candidate" ]; then
            LOG_FILE="$_candidate"
            break
        fi
    done
fi

if [ ! -f "$LOG_FILE" ]; then
    echo "Log file not found: $LOG_FILE"
    exit 1
fi

# Installs an apt package unattended if the tool isn't already on PATH,
# trying root first, then passwordless sudo; falls back to a clear error
# if neither is available (e.g. non-Debian, no privileges).
_ensure_tool() {
    local tool="$1" apt_pkg="$2"
    command -v "$tool" >/dev/null 2>&1 && return 0
    echo "$tool was not found on PATH. Attempting to install it now (apt install $apt_pkg)..."
    if command -v apt-get >/dev/null 2>&1; then
        if [ "$(id -u)" -eq 0 ]; then
            DEBIAN_FRONTEND=noninteractive apt-get install -y "$apt_pkg" >/dev/null 2>&1
        elif command -v sudo >/dev/null 2>&1; then
            DEBIAN_FRONTEND=noninteractive sudo -n apt-get install -y "$apt_pkg" >/dev/null 2>&1
        fi
    fi
    command -v "$tool" >/dev/null 2>&1
}

# Every external command this script (and pdf_lib.sh) actually shells out
# to, mapped to the Debian/Kali/Ubuntu apt package that provides it.
for _dep in "grep:grep" "sed:sed" "awk:gawk" "sort:coreutils" "uniq:coreutils" \
            "cut:coreutils" "fold:coreutils" "mktemp:coreutils" "date:coreutils" \
            "tr:coreutils" "wc:coreutils"; do
    _tool="${_dep%%:*}"; _pkg="${_dep##*:}"
    if ! _ensure_tool "$_tool" "$_pkg"; then
        echo "Required tool '$_tool' is missing and could not be installed automatically (apt install $_pkg)."
        exit 1
    fi
done

# pdf_lib.sh is a required co-located file, not an installable package: if
# this script was copied out of its scripts/ folder on its own (a common
# mistake when grabbing just one file to test), look for pdf_lib.sh in the
# other places it's plausible to have been copied to before giving up with
# ONE clear, actionable message instead of a cascade of "command not
# found" errors once every pdf_* call below starts failing.
PDF_LIB=""
for _candidate in "$SCRIPT_DIR/pdf_lib.sh" "$SCRIPT_DIR/../scripts/pdf_lib.sh" "$SCRIPT_DIR/scripts/pdf_lib.sh"; do
    if [ -f "$_candidate" ]; then
        PDF_LIB="$_candidate"
        break
    fi
done
if [ -z "$PDF_LIB" ]; then
    echo "pdf_lib.sh not found (checked next to this script, ../scripts/, and ./scripts/)."
    echo "This script was likely copied out of its scripts/ folder without its sibling pdf_lib.sh."
    echo "Fix: run it from its original scripts/ directory, or copy pdf_lib.sh alongside it."
    exit 1
fi
source "$PDF_LIB"

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
