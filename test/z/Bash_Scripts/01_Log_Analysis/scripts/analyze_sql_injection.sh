#!/bin/bash
#
# analyze_sql_injection.sh
# Target: logs/01_sql_injection_meridian_retail.log (Meridian Retail Group)
#
# Detects SQL injection recon, sqlmap fingerprinting, blind boolean-based
# extraction, UNION-based data dumps, authentication bypass, credential
# stuffing account takeovers, and post-bypass exfiltration in a web access
# log mixed with ordinary customer traffic.
#
# Prints the analysis to the console AND renders a PDF incident report,
# using nothing but Bash and coreutils (grep/awk/sed/fold) plus the
# co-located pdf_lib.sh, a small dependency-free PDF writer. No Python,
# no external report-rendering tool required.
#
# Usage: ./analyze_sql_injection.sh <path-to-log>

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="${1:-$SCRIPT_DIR/../logs/01_sql_injection_meridian_retail.log}"

if [ ! -f "$LOG_FILE" ]; then
    echo "Log file not found: $LOG_FILE"
    exit 1
fi

source "$SCRIPT_DIR/pdf_lib.sh"

# Real HTTP request lines cannot contain a literal space, so SQLi payloads
# with spaces are percent-encoded (%20) in the raw log, exactly like a real
# browser or tool would send them. Grep patterns like "OR 1=1" or "UNION
# SELECT" need a decoded working copy to still match.
DECODED_FILE="$(mktemp)"
trap 'rm -f "$DECODED_FILE"' EXIT
sed 's/%20/ /g' "$LOG_FILE" > "$DECODED_FILE"

echo "=================================================================="
echo " SQL INJECTION INCIDENT REPORT"
echo " Source log : $LOG_FILE"
echo "=================================================================="

pdf_init "SQL Injection Incident Report" "Meridian Retail Group - shop.meridianretail.com" "$LOG_FILE"

echo
echo "[1] Requests containing classic SQLi payload patterns"
echo "------------------------------------------------------------------"
TOTAL_SQLI=$(grep -Eic "UNION SELECT|OR 1=1|OR '1'='1|SLEEP\(|extractvalue|information_schema|--\s*-|'--|blind_probe" "$DECODED_FILE" || true)
echo "Total suspicious requests: $TOTAL_SQLI"

echo
echo "[2] Top source IPs sending SQLi payloads"
echo "------------------------------------------------------------------"
TOP_SQLI_IPS=$(grep -Ei "UNION SELECT|OR 1=1|SLEEP\(|extractvalue|information_schema|blind_probe" "$DECODED_FILE" \
    | awk '{print $1}' | sort | uniq -c | sort -rn | head -10)
echo "$TOP_SQLI_IPS"

echo
echo "[3] sqlmap and automated tool fingerprints (User-Agent based detection)"
echo "------------------------------------------------------------------"
UA_FINGERPRINTS=$(grep -oE '"(sqlmap[^"]*|python-requests[^"]*|[^"]*Acunetix[^"]*)"' "$LOG_FILE" | sort | uniq -c | sort -rn)
echo "$UA_FINGERPRINTS"

echo
echo "[4] UNION-based data dump attempts (tables/columns/credentials pulled)"
echo "------------------------------------------------------------------"
UNION_DUMPS=$(grep -E "UNION SELECT (table_name|column_name|username|card_number)" "$DECODED_FILE" \
    | sed -E 's/^([0-9.]+).*"(GET|POST) ([^ ]+) HTTP.*/\1 -> \3/' \
    | head -20)
echo "$UNION_DUMPS"
DUMPED_TABLES=$(grep -oE "FROM (users|saved_payment_methods|admin_sessions|gift_cards|employee_payroll_view)" "$DECODED_FILE" | awk '{print $2}' | sort -u)

echo
echo "[5] Blind boolean-based extraction (high-volume probing)"
echo "------------------------------------------------------------------"
BLIND_COUNT=$(grep -c "blind_probe" "$LOG_FILE" || true)
echo "Blind extraction requests: $BLIND_COUNT"
BLIND_IPS=$(grep "blind_probe" "$LOG_FILE" | awk '{print $1}' | sort | uniq -c | sort -rn | head -5)
echo "$BLIND_IPS"

echo
echo "[6] Authentication bypass attempt"
echo "------------------------------------------------------------------"
AUTH_BYPASS_LINE=""
if grep -q "AUTH_BYPASS_SUCCESS" "$LOG_FILE"; then
    while read -r line; do
        ip=$(echo "$line" | awk '{print $1}')
        session=$(echo "$line" | grep -oE "session=[a-zA-Z0-9_]+")
        echo "ALERT: auth bypass from $ip ($session)"
        AUTH_BYPASS_LINE="Auth bypass from $ip, $session"
    done < <(grep "AUTH_BYPASS_SUCCESS" "$LOG_FILE")
else
    echo "No confirmed auth bypass found."
    AUTH_BYPASS_LINE="No confirmed auth bypass found."
fi

echo
echo "[7] Post-bypass admin actions using the hijacked session"
echo "------------------------------------------------------------------"
SESSION=$(grep -oE "session=[a-zA-Z0-9_]+" "$LOG_FILE" | head -1 | cut -d= -f2)
POST_BYPASS_ACTIONS=""
if [ -n "${SESSION:-}" ]; then
    POST_BYPASS_ACTIONS=$(grep "cookie=${SESSION}" "$LOG_FILE" \
        | sed -E 's/^([0-9.]+).*"(GET|POST) ([^ ]+) HTTP\/[0-9.]+" ([0-9]+) ([0-9]+).*/\1 status=\4 bytes=\5 path=\3/')
    echo "$POST_BYPASS_ACTIONS"
fi

echo
echo "[8] Credential stuffing account takeovers"
echo "------------------------------------------------------------------"
TAKEOVER_COUNT=$(grep -c "ACCOUNT_TAKEOVER_SUCCESS" "$LOG_FILE" || true)
echo "Compromised customer accounts: $TAKEOVER_COUNT"
TAKEOVER_ACCOUNTS=$(grep "ACCOUNT_TAKEOVER_SUCCESS" "$LOG_FILE" | grep -oE "username=[^&]+" | sed 's/username=//')
echo "$TAKEOVER_ACCOUNTS"

echo
echo "[9] Data exfiltration volume (EXFIL_CANDIDATE responses)"
echo "------------------------------------------------------------------"
TOTAL_BYTES=$(grep "EXFIL_CANDIDATE" "$LOG_FILE" | awk '{for(i=1;i<=NF;i++) if ($i ~ /^[0-9]+$/ && $i+0 > 1000) {print $i; break}}' | awk '{s+=$1} END{print s+0}')
EXFIL_COUNT=$(grep -c "EXFIL_CANDIDATE" "$LOG_FILE" || true)
echo "Flagged exfil requests : $EXFIL_COUNT"
echo "Approx bytes transferred: $TOTAL_BYTES"

echo
echo "[10] WAF blocked destructive attempts (stacked queries)"
echo "------------------------------------------------------------------"
WAF_BLOCKS=$(grep "WAF_BLOCK" "$LOG_FILE" | sed -E 's/^([0-9.]+).*"(GET|POST) ([^ ]+) HTTP.*/blocked: \1 -> \3/')
echo "$WAF_BLOCKS"

echo
echo "[11] SOC / WAF alert summary"
echo "------------------------------------------------------------------"
ALERT_LINE=$(grep "SECURITY_ALERT" "$LOG_FILE" || echo "No SOC alert recorded in this log.")
echo "$ALERT_LINE"

echo
echo "=================================================================="
echo " END OF REPORT"
echo "=================================================================="

# ---- Build the PDF report --------------------------------------------
pdf_banner "CRITICAL: $TOTAL_SQLI SQLi requests, $BLIND_COUNT blind-extraction probes, $TAKEOVER_COUNT account takeover(s), ~$TOTAL_BYTES bytes exfiltrated"

pdf_section "Executive Summary"
pdf_kv "Suspicious SQLi requests" "$TOTAL_SQLI"
pdf_kv "Blind extraction probes" "$BLIND_COUNT"
pdf_kv "Authentication bypass" "$AUTH_BYPASS_LINE"
pdf_kv "Customer accounts taken over" "$TAKEOVER_COUNT"
pdf_kv "Data exfiltrated (hijacked session)" "~$TOTAL_BYTES bytes across $EXFIL_COUNT requests"
pdf_kv "WAF blocked requests" "$(printf '%s\n' "$WAF_BLOCKS" | grep -c .)"

pdf_section "Top Source IPs Sending SQLi Payloads"
pdf_table_header "$(printf '%-20s %10s' 'Source IP' 'Requests')"
while read -r cnt ip; do
    [ -z "$ip" ] && continue
    pdf_table_line "$(printf '%-20s %10s' "$ip" "$cnt")"
done <<< "$TOP_SQLI_IPS"
BAR_MAX=$(printf '%s\n' "$TOP_SQLI_IPS" | awk '{print $1}' | sort -rn | head -1)
[ -z "$BAR_MAX" ] && BAR_MAX=1
while read -r cnt ip; do
    [ -z "$ip" ] && continue
    pdf_bar "$ip" "$cnt" "$BAR_MAX"
done <<< "$TOP_SQLI_IPS"

pdf_section "Automated Tool Fingerprints"
while read -r cnt ua; do
    [ -z "$ua" ] && continue
    pdf_table_line "$(printf '%-6s %s' "$cnt" "$ua")"
done <<< "$UA_FINGERPRINTS"

pdf_section "UNION-Based Data Dump Targets"
pdf_text "Tables enumerated and dumped via UNION SELECT:"
while read -r tbl; do
    [ -z "$tbl" ] && continue
    pdf_table_line "  - $tbl"
done <<< "$DUMPED_TABLES"

pdf_section "Blind Boolean-Based Extraction"
pdf_text "A second actor used near-identical, incrementally-varying requests to extract data one character at a time via ASCII/SUBSTRING comparisons, a hallmark of blind SQL injection."
while read -r cnt ip; do
    [ -z "$ip" ] && continue
    pdf_table_line "$(printf '%-20s %10s' "$ip" "$cnt")"
done <<< "$BLIND_IPS"

pdf_section "Authentication Bypass"
pdf_text "$AUTH_BYPASS_LINE"

pdf_section "Post-Bypass Admin Actions and Exfiltration"
pdf_table_header "$(printf '%-16s %-45s %8s' 'IP' 'Path' 'Bytes')"
while read -r ip status bytes path; do
    [ -z "$ip" ] && continue
    p=$(echo "$path" | sed 's/path=//')
    b=$(echo "$bytes" | sed 's/bytes=//')
    pdf_table_line "$(printf '%-16s %-45s %8s' "$ip" "${p:0:45}" "$b")"
done <<< "$POST_BYPASS_ACTIONS"

pdf_section "Credential Stuffing: Compromised Customer Accounts"
pdf_text "$TAKEOVER_COUNT customer accounts were successfully taken over using credentials obtained from the earlier data dump, then used to place fraudulent orders."
while read -r acct; do
    [ -z "$acct" ] && continue
    pdf_table_line "  - $acct"
done <<< "$TAKEOVER_ACCOUNTS"

pdf_section "WAF Blocked Destructive Attempts"
while read -r line; do
    [ -z "$line" ] && continue
    pdf_table_line "$line"
done <<< "$WAF_BLOCKS"

pdf_section "SOC / WAF Alerts"
pdf_text "$ALERT_LINE"

OUT_PDF="$SCRIPT_DIR/../reports/01_sql_injection_report.pdf"
pdf_save "$OUT_PDF" > /dev/null
echo
echo "PDF report written to: $OUT_PDF"
