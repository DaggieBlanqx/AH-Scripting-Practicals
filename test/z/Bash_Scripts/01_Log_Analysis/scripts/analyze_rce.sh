#!/bin/bash
#
# analyze_rce.sh
# Target: logs/02_rce_vantage_cloud_systems.log (Vantage Cloud Systems)
#
# Detects reconnaissance, JNDI/Log4Shell style injection, malicious file
# upload, webshell command execution, server takeover actions, internal
# network sweeps, and outbound C2 beaconing across two independently
# compromised hosts, mixed with ordinary portal traffic.
#
# Prints the analysis to the console AND renders a PDF incident report,
# using nothing but Bash and coreutils (grep/awk/sed/fold) plus the
# co-located pdf_lib.sh, a small dependency-free PDF writer. No Python,
# no external report-rendering tool required.
#
# Usage: ./analyze_rce.sh <path-to-log>

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="${1:-$SCRIPT_DIR/../logs/02_rce_vantage_cloud_systems.log}"

if [ ! -f "$LOG_FILE" ]; then
    echo "Log file not found: $LOG_FILE"
    exit 1
fi

source "$SCRIPT_DIR/pdf_lib.sh"

echo "=================================================================="
echo " REMOTE CODE EXECUTION INCIDENT REPORT"
echo " Source log : $LOG_FILE"
echo "=================================================================="

pdf_init "Remote Code Execution Incident Report" "Vantage Cloud Systems - portal.vantagecloud.io" "$LOG_FILE"

echo
echo "[1] Reconnaissance and vulnerability probing"
echo "------------------------------------------------------------------"
RECON_HITS=$(grep -Ei "actuator|jndi:|manager/html|\.git/config|console/" "$LOG_FILE" \
    | sed -E 's/^([0-9.]+).*"(GET|POST) ([^ ]+) HTTP.*/\1 -> \3/' | head -15)
echo "$RECON_HITS"

echo
echo "[2] JNDI / Log4Shell style injection attempts"
echo "------------------------------------------------------------------"
JNDI_HITS=$(grep -Eo '\$\{jndi:[a-z]+://[^}]+\}' "$LOG_FILE" | sort | uniq -c)
echo "$JNDI_HITS"

echo
echo "[3] Malicious file upload"
echo "------------------------------------------------------------------"
UPLOADS=$(grep "documents/upload" "$LOG_FILE" | grep -i "filename=" \
    | sed -E 's/.*(filename=[^ ]+).*/\1/')
echo "$UPLOADS"

echo
echo "[4] Webshell command execution timeline (sample, excludes network sweep)"
echo "------------------------------------------------------------------"
WEBSHELL_CMDS=$(grep "WEBSHELL_EXEC" "$LOG_FILE" | grep -v "internal_scan" \
    | sed -E 's/^([0-9.]+) .*\[([^]]+)\].*cmd=([^ &"]+).*/\2 | attacker=\1 | cmd=\3/' \
    | sed 's/+/ /g' | head -30)
echo "$WEBSHELL_CMDS"

echo
echo "[5] Server takeover indicators (across all compromised hosts)"
echo "------------------------------------------------------------------"
TAKEOVER_COUNT=$(grep -c "SERVER_TAKEOVER" "$LOG_FILE" || true)
echo "Takeover-tagged requests: $TAKEOVER_COUNT"
TAKEOVER_CMDS=$(grep "SERVER_TAKEOVER" "$LOG_FILE" | grep -oE "cmd=[^ &\"]+" | sed 's/+/ /g;s/cmd=//' | head -20)
echo "$TAKEOVER_CMDS"

echo
echo "[6] Internal network lateral movement sweep"
echo "------------------------------------------------------------------"
SWEEP_COUNT=$(grep -c "internal_scan" "$LOG_FILE" || true)
echo "Internal hosts probed on port 22 from the webshell: $SWEEP_COUNT"

echo
echo "[7] Unique attacker source IPs"
echo "------------------------------------------------------------------"
ATTACKER_IPS=$(grep -E "WEBSHELL_EXEC|SERVER_TAKEOVER|jndi:" "$LOG_FILE" | awk '{print $1}' | sort -u)
echo "$ATTACKER_IPS"

echo
echo "[8] Outbound C2 beacon activity (firewall log lines)"
echo "------------------------------------------------------------------"
BEACON_COUNT=$(grep -c "FIREWALL_LOG" "$LOG_FILE" || true)
echo "Beacon events observed: $BEACON_COUNT"
BEACON_DESTS=$(grep "FIREWALL_LOG" "$LOG_FILE" | grep -oE "dst=[0-9.]+ dport=[0-9]+" | sort | uniq -c | sort -rn)
echo "$BEACON_DESTS"

echo
echo "[9] Webshell-hunting bot (third-party backdoor discovery attempts)"
echo "------------------------------------------------------------------"
HUNTER_COUNT=$(grep -c "webshell-hunter" "$LOG_FILE" || true)
echo "Requests probing for other pre-existing webshells: $HUNTER_COUNT"

echo
echo "[10] EDR / SOC detection and containment"
echo "------------------------------------------------------------------"
ALERT_LINE=$(grep "SECURITY_ALERT" "$LOG_FILE" || echo "No EDR alert recorded in this log.")
echo "$ALERT_LINE"

echo
echo "=================================================================="
echo " END OF REPORT"
echo "=================================================================="

# ---- Build the PDF report --------------------------------------------
N_HOSTS=$(printf '%s\n' "$ATTACKER_IPS" | grep -c .)
pdf_banner "CRITICAL: $N_HOSTS attacker host(s), $TAKEOVER_COUNT server takeover action(s), $BEACON_COUNT C2 beacon events, active outbound C2 traffic detected"

pdf_section "Executive Summary"
pdf_kv "Recon/probing requests" "$(printf '%s\n' "$RECON_HITS" | grep -c .)"
pdf_kv "JNDI/Log4Shell attempts" "$(printf '%s\n' "$JNDI_HITS" | awk '{s+=$1} END{print s+0}')"
pdf_kv "Malicious file uploads" "$(printf '%s\n' "$UPLOADS" | grep -c .)"
pdf_kv "Webshell commands executed" "$(grep -c "WEBSHELL_EXEC" "$LOG_FILE" || true)"
pdf_kv "Server takeover actions" "$TAKEOVER_COUNT"
pdf_kv "Internal network sweep requests" "$SWEEP_COUNT"
pdf_kv "C2 beacon events observed" "$BEACON_COUNT"
pdf_kv "Webshell-hunting bot requests" "$HUNTER_COUNT"

pdf_section "Reconnaissance and Vulnerability Probing"
while read -r line; do
    [ -z "$line" ] && continue
    pdf_table_line "$line"
done <<< "$RECON_HITS"

pdf_section "JNDI / Log4Shell Style Injection Attempts"
while read -r cnt payload; do
    [ -z "$payload" ] && continue
    pdf_table_line "$(printf '%-6s %s' "$cnt" "$payload")"
done <<< "$JNDI_HITS"

pdf_section "Malicious File Upload"
while read -r line; do
    [ -z "$line" ] && continue
    pdf_table_line "$line"
done <<< "$UPLOADS"

pdf_section "Webshell Command Execution Timeline (sample)"
while read -r line; do
    [ -z "$line" ] && continue
    pdf_table_line "$line"
done <<< "$WEBSHELL_CMDS"

pdf_section "Server Takeover Indicators"
pdf_text "$TAKEOVER_COUNT commands were tagged SERVER_TAKEOVER (new privileged user, sudoers edit, cryptominer download, persistence via cron)."
while read -r cmd; do
    [ -z "$cmd" ] && continue
    pdf_table_line "  - $cmd"
done <<< "$TAKEOVER_CMDS"

pdf_section "Internal Network Lateral Movement"
pdf_text "The webshell was used to sweep $SWEEP_COUNT internal hosts on port 22, indicating an attempt to move laterally beyond the compromised web server."

pdf_section "Outbound Command-and-Control Beaconing"
pdf_text "$BEACON_COUNT total beacon events observed. Destinations:"
while read -r cnt rest; do
    [ -z "$rest" ] && continue
    pdf_table_line "$(printf '%-6s %s' "$cnt" "$rest")"
done <<< "$BEACON_DESTS"
BAR_MAX=$(printf '%s\n' "$BEACON_DESTS" | awk '{print $1}' | sort -rn | head -1)
[ -z "$BAR_MAX" ] && BAR_MAX=1
while read -r cnt rest; do
    [ -z "$rest" ] && continue
    pdf_bar "$rest" "$cnt" "$BAR_MAX"
done <<< "$BEACON_DESTS"

pdf_section "Webshell-Hunting Bot (Third-Party Backdoor Discovery Attempts)"
pdf_text "$HUNTER_COUNT requests probed for common pre-existing webshell filenames left by other actors. All returned 404 in this incident."

pdf_section "Unique Attacker Source IPs"
while read -r ip; do
    [ -z "$ip" ] && continue
    pdf_table_line "  - $ip"
done <<< "$ATTACKER_IPS"

pdf_section "SOC / EDR Detection and Containment"
pdf_text "$ALERT_LINE"

OUT_PDF="$SCRIPT_DIR/../reports/02_rce_report.pdf"
pdf_save "$OUT_PDF" > /dev/null
echo
echo "PDF report written to: $OUT_PDF"
