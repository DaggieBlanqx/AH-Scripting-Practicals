#!/bin/bash
#
# analyze_bruteforce.sh
# Target: logs/05_bruteforce_solstice_health_networks.log (Solstice Health Networks)
#
# Classic SSH auth.log analysis: separates ordinary internet background
# scanning noise from a focused credential-stuffing campaign against real
# employee usernames, finds the successful compromise, and traces lateral
# movement and data exfiltration, mixed with routine legitimate SSH
# activity.
#
# Prints the analysis to the console AND renders a PDF incident report,
# using nothing but Bash and coreutils (grep/awk/sed/fold) plus the
# co-located pdf_lib.sh, a small dependency-free PDF writer. No Python,
# no external report-rendering tool required.
#
# Usage: ./analyze_bruteforce.sh <path-to-log>

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="${1:-$SCRIPT_DIR/../logs/05_bruteforce_solstice_health_networks.log}"

if [ ! -f "$LOG_FILE" ]; then
    echo "Log file not found: $LOG_FILE"
    exit 1
fi

source "$SCRIPT_DIR/pdf_lib.sh"

echo "=================================================================="
echo " BRUTE FORCE / CREDENTIAL STUFFING INCIDENT REPORT"
echo " Source log : $LOG_FILE"
echo "=================================================================="

pdf_init "Brute Force / Credential Stuffing Incident Report" "Solstice Health Networks - vpn.solsticehealth.org" "$LOG_FILE"

echo
echo "[1] Legitimate vs failed login volume"
echo "------------------------------------------------------------------"
LEGIT_LOGINS=$(grep -c "Accepted publickey" "$LOG_FILE" || true)
FAILED_COUNT=$(grep -c "Failed password" "$LOG_FILE" || true)
echo "Legitimate successful logins: $LEGIT_LOGINS"
echo "Failed login attempts: $FAILED_COUNT"

echo
echo "[2] Top 10 source IPs by failed login count"
echo "------------------------------------------------------------------"
TOP_FAIL_IPS=$(grep "Failed password" "$LOG_FILE" | grep -oE "from [0-9.]+" | awk '{print $2}' \
    | sort | uniq -c | sort -rn | head -10)
echo "$TOP_FAIL_IPS"

echo
echo "[3] Failed attempts per targeted username (top 15)"
echo "------------------------------------------------------------------"
TOP_USERS=$(grep "Failed password" "$LOG_FILE" | sed -E 's/.*Failed password for (invalid user )?([^ ]+) from.*/\2/' \
    | sort | uniq -c | sort -rn | head -15)
echo "$TOP_USERS"

echo
echo "[4] Credential stuffing IPs: targeting multiple valid (non-invalid-user) accounts"
echo "------------------------------------------------------------------"
# Ordinary scanners hammer a single "invalid user" over and over. A source IP
# that fails password checks against several *different* real usernames is a
# much stronger credential-stuffing signal than raw failure volume.
STUFFING_IPS=$(grep "Failed password for " "$LOG_FILE" | grep -v "invalid user" \
    | sed -E 's/.*Failed password for ([^ ]+) from ([0-9.]+).*/\2 \1/' \
    | sort -u | awk '{print $1}' | sort | uniq -c | sort -rn \
    | awk '$1 > 1 {print $2 " targeted " $1 " distinct valid usernames"}')
echo "$STUFFING_IPS"

echo
echo "[5] Successful compromise (accepted password, not publickey)"
echo "------------------------------------------------------------------"
COMPROMISE_LINE=$(grep "Accepted password" "$LOG_FILE")
echo "$COMPROMISE_LINE"

echo
echo "[6] Privileged commands executed after compromise (sudo trail)"
echo "------------------------------------------------------------------"
SUDO_TRAIL=$(grep "sudo:" "$LOG_FILE" | sed -E 's/^([A-Za-z]+ [0-9]+ [0-9:]+).*sudo: (.*)$/\1 | \2/')
echo "$SUDO_TRAIL"

echo
echo "[7] Lateral movement to internal hosts"
echo "------------------------------------------------------------------"
LATERAL_HOSTS=$(grep "lateral movement" "$LOG_FILE" | grep -oE "target: [^)]+\)" | sed 's/target: //;s/)//')
echo "$LATERAL_HOSTS"

echo
echo "[8] Data staged or exfiltrated"
echo "------------------------------------------------------------------"
EXFIL_LINES=$(grep -E "scp\[|outbound-fw" "$LOG_FILE")
echo "$EXFIL_LINES"

echo
echo "[9] Response: bans issued and SOC alert"
echo "------------------------------------------------------------------"
RESPONSE_LINES=$(grep -E "fail2ban|SECURITY_ALERT" "$LOG_FILE")
echo "$RESPONSE_LINES"

echo
echo "=================================================================="
echo " END OF REPORT"
echo "=================================================================="

# ---- Build the PDF report --------------------------------------------
STUFFING_COUNT=$(printf '%s\n' "$STUFFING_IPS" | grep -c .)
COMPROMISE_COUNT=$(printf '%s\n' "$COMPROMISE_LINE" | grep -c .)
LATERAL_COUNT=$(printf '%s\n' "$LATERAL_HOSTS" | grep -c .)

pdf_banner "CRITICAL: $COMPROMISE_COUNT account(s) compromised, lateral movement to $LATERAL_COUNT internal host(s), data exfiltration detected"

pdf_section "Executive Summary"
pdf_kv "Legitimate successful logins" "$LEGIT_LOGINS (publickey)"
pdf_kv "Total failed login attempts" "$FAILED_COUNT"
pdf_kv "IPs showing credential-stuffing pattern" "$STUFFING_COUNT"
pdf_kv "Successful compromises" "$COMPROMISE_COUNT"
pdf_kv "Lateral movement events" "$LATERAL_COUNT"
pdf_kv "Data exfiltration events" "$(printf '%s\n' "$EXFIL_LINES" | grep -c .)"

pdf_section "Top Source IPs by Failed Login Count"
pdf_table_header "$(printf '%-20s %10s' 'Source IP' 'Attempts')"
while read -r cnt ip; do
    [ -z "$ip" ] && continue
    pdf_table_line "$(printf '%-20s %10s' "$ip" "$cnt")"
done <<< "$TOP_FAIL_IPS"
BAR_MAX=$(printf '%s\n' "$TOP_FAIL_IPS" | awk '{print $1}' | sort -rn | head -1)
[ -z "$BAR_MAX" ] && BAR_MAX=1
while read -r cnt ip; do
    [ -z "$ip" ] && continue
    pdf_bar "$ip" "$cnt" "$BAR_MAX"
done <<< "$TOP_FAIL_IPS"

pdf_section "Most-Targeted Usernames"
while read -r cnt user; do
    [ -z "$user" ] && continue
    pdf_table_line "$(printf '%-20s %10s' "$user" "$cnt")"
done <<< "$TOP_USERS"

pdf_section "Credential Stuffing Detection"
pdf_text "Ordinary internet scanners repeatedly hammer a single default username. A source IP that fails password checks against several different real usernames is a much stronger credential-stuffing signal than raw failure volume."
while read -r line; do
    [ -z "$line" ] && continue
    pdf_table_line "$line"
done <<< "$STUFFING_IPS"

pdf_section "Successful Compromise"
pdf_text "$COMPROMISE_LINE"

pdf_section "Post-Compromise Privileged Commands (sudo trail)"
while read -r line; do
    [ -z "$line" ] && continue
    pdf_table_line "$line"
done <<< "$SUDO_TRAIL"

pdf_section "Lateral Movement"
while read -r line; do
    [ -z "$line" ] && continue
    pdf_table_line "  - $line"
done <<< "$LATERAL_HOSTS"

pdf_section "Data Exfiltration"
while read -r line; do
    [ -z "$line" ] && continue
    pdf_table_line "$line"
done <<< "$EXFIL_LINES"

pdf_section "Response: Bans and SOC Alert"
while read -r line; do
    [ -z "$line" ] && continue
    pdf_table_line "$line"
done <<< "$RESPONSE_LINES"

OUT_PDF="$SCRIPT_DIR/../reports/05_bruteforce_report.pdf"
pdf_save "$OUT_PDF" > /dev/null
echo
echo "PDF report written to: $OUT_PDF"
