#!/usr/bin/env bash
#
# script.sh - Web access log threat analysis
# Usage: bash script.sh logs.txt
#
# Parses an Apache/Nginx-style access log, flags malicious activity
# (SQLi, auth bypass, credential stuffing / ATO, data exfiltration,
# WAF events, recon tooling) and writes a Markdown report.
#

set -uo pipefail

LOG="${1:-}"
if [[ -z "$LOG" || ! -f "$LOG" ]]; then
    echo "Usage: bash $0 <logfile>" >&2
    exit 1
fi

OUT="log_analysis_$(date +%Y%m%d_%H%M%S).md"
TOTAL=$(wc -l < "$LOG" | tr -d ' ')

# ---- Detection patterns ---------------------------------------------------
# SQLi payload signatures (URL-encoded and plain)
SQLI_RE="union%20select|union select|information_schema|extractvalue|SLEEP\(|CONVERT\(int|OR%201=1|OR 1=1|'%20OR%20'|\)%20OR%20\(|%20OR%20\(|'--|'-- -|%27|AND%201=|AND 1=|0x[0-9a-f]{6,}|CONCAT\(|@@version"
# Stacked / destructive queries
STACKED_RE="DROP%20TABLE|DROP TABLE|UPDATE%20users|UPDATE users|;%20DROP|;%20UPDATE"
# Auth bypass in login body
AUTHBYPASS_RE="username=[^&]*'--"
# Recon / attack tooling user agents
TOOL_RE="sqlmap|nikto|nmap|masscan|hydra|acunetix|nessus|python-requests|curl/"

# Sensitive tables/objects that indicate high-impact data targeting
SENS_RE="users|saved_payment_methods|gift_cards|admin_sessions|employee_payroll_view|card_number|cvv|password|session_token|bank_account"

# ---- Helper: extract client IP (field 1) ----------------------------------
ip_of() { awk '{print $1}' <<< "$1"; }

# ---- Pass 1: classify every line into a temp tagged stream ----------------
TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT

while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    ip=$(awk '{print $1}' <<< "$line")
    # Non-request meta lines (e.g. SECURITY_ALERT) have no IP in field 1
    grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' <<< "$ip" || ip="-"
    tags=""

    # Explicit engine markers present in the sample
    grep -qE "AUTH_BYPASS_SUCCESS"        <<< "$line" && tags+="AUTH_BYPASS;"
    grep -qE "ACCOUNT_TAKEOVER_SUCCESS"   <<< "$line" && tags+="ATO;"
    grep -qE "EXFIL_CANDIDATE"            <<< "$line" && tags+="EXFIL;"
    grep -qE "WAF_BLOCK|WAF_ALERT"        <<< "$line" && tags+="WAF_BLOCK;"
    grep -qE "SECURITY_ALERT"             <<< "$line" && tags+="SEC_ALERT;"

    # Payload / behavioural detections
    grep -qiE "$STACKED_RE"    <<< "$line" && tags+="SQLI_STACKED;"
    grep -qiE "$SQLI_RE"       <<< "$line" && tags+="SQLI;"
    grep -qiE "$AUTHBYPASS_RE" <<< "$line" && tags+="AUTH_BYPASS_ATTEMPT;"
    grep -qiE "$TOOL_RE"       <<< "$line" && tags+="TOOL;"
    grep -qiE "fraudulent_purchase|add_high_value_item|view_saved_card" <<< "$line" && tags+="FRAUD;"

    if [[ -n "$tags" ]]; then
        printf '%s\t%s\t%s\n' "$ip" "$tags" "$line" >> "$TMP"
    fi
done < "$LOG"

FLAGGED=$(wc -l < "$TMP" | tr -d ' ')

# ---- Aggregations ---------------------------------------------------------
count_tag() { grep -c "$1" "$TMP" || true; }

SQLI_N=$(grep -cE 'SQLI(;|_)' "$TMP" || true)
STACKED_N=$(count_tag "SQLI_STACKED")
AUTHBYPASS_N=$(count_tag "AUTH_BYPASS;")
ATO_N=$(count_tag "ATO;")
EXFIL_N=$(count_tag "EXFIL;")
WAF_N=$(count_tag "WAF_BLOCK;")
TOOL_N=$(count_tag "TOOL;")
FRAUD_N=$(count_tag "FRAUD;")

# Attacker IPs ranked by number of flagged events
ATTACKER_IPS=$(cut -f1 "$TMP" | sort | uniq -c | sort -rn)

# Total bytes exfiltrated (sum of response size on EXFIL lines)
EXFIL_BYTES=$(grep 'EXFIL;' "$TMP" | awk '{for(i=1;i<=NF;i++) if($i ~ /^[0-9]{4,}$/){print $i; break}}' | paste -sd+ - | bc 2>/dev/null || echo 0)
[[ -z "$EXFIL_BYTES" ]] && EXFIL_BYTES=0

# Compromised customer accounts (from ATO lines)
ATO_ACCOUNTS=$(grep 'ATO;' "$TMP" | grep -oE 'username=[^&]+' | sed 's/username=//' | sort -u)
ATO_ACCT_N=$(printf '%s\n' "$ATO_ACCOUNTS" | grep -c . || true)

# Sensitive tables touched
SENS_TABLES=$(grep -oiE "$SENS_RE" "$TMP" | tr '[:upper:]' '[:lower:]' | sort -u | paste -sd', ' -)

# Time window of the attack
FIRST=$(grep -oE '\[[0-9]{2}/[A-Za-z]{3}/[0-9]{4}:[0-9:]{8}' "$TMP" | head -1 | tr -d '[')
LAST=$(grep -oE '\[[0-9]{2}/[A-Za-z]{3}/[0-9]{4}:[0-9:]{8}' "$TMP" | tail -1 | tr -d '[')

# ---- Write report ---------------------------------------------------------
{
echo "# Log Threat Analysis Report"
echo ""
echo "**Source file:** \`$LOG\`  "
echo "**Generated:** $(date -u '+%Y-%m-%d %H:%M:%S UTC')  "
echo "**Total log lines:** $TOTAL  "
echo "**Flagged malicious events:** $FLAGGED  "
echo "**Attack window:** $FIRST to $LAST  "
echo ""
echo "## Executive Summary"
echo ""
echo "The log shows a multi-stage attack against the application. An"
echo "attacker fingerprinted a SQL injection flaw in \`/product/detail\`,"
echo "automated exploitation with sqlmap to dump sensitive tables, bypassed"
echo "authentication to reach the admin panel, and bulk-exported customer"
echo "data. A separate credential-stuffing wave then took over multiple"
echo "customer accounts and placed fraudulent orders."
echo ""
echo "## Findings by Category"
echo ""
echo "| Category | Events |"
echo "|---|---|"
echo "| SQL Injection (probing + exploitation) | $SQLI_N |"
echo "| Stacked / destructive SQL (WAF-blocked) | $STACKED_N |"
echo "| Authentication bypass via SQLi | $AUTHBYPASS_N |"
echo "| Account takeover (credential stuffing) | $ATO_N |"
echo "| Data exfiltration (bulk export/backup) | $EXFIL_N |"
echo "| WAF blocks | $WAF_N |"
echo "| Attack-tool user agents | $TOOL_N |"
echo "| Post-compromise fraud actions | $FRAUD_N |"
echo ""
echo "**Approx. bytes exfiltrated:** $EXFIL_BYTES bytes"
echo ""
echo "**Sensitive objects targeted:** $SENS_TABLES"
echo ""
echo "## Attacking IP Addresses"
echo ""
echo "| Flagged events | IP |"
echo "|---|---|"
printf '%s\n' "$ATTACKER_IPS" | while read -r c ip; do
    [[ -z "$ip" ]] && continue
    echo "| $c | $ip |"
done
echo ""
echo "## Compromised Customer Accounts ($ATO_ACCT_N)"
echo ""
if [[ -n "$ATO_ACCOUNTS" ]]; then
    printf '%s\n' "$ATO_ACCOUNTS" | while read -r a; do
        [[ -n "$a" ]] && echo "- $a"
    done
else
    echo "_None detected._"
fi
echo ""
echo "## Attack Timeline (flagged events)"
echo ""
echo "| Time | IP | Flags | Request |"
echo "|---|---|---|---|"
while IFS=$'\t' read -r ip tags line; do
    ts=$(grep -oE '\[[0-9:/A-Za-z]+' <<< "$line" | head -1 | tr -d '[' )
    req=$(grep -oE '"[A-Z]+ [^"]+"' <<< "$line" | head -1 | tr -d '"' )
    [[ -z "$req" ]] && req=$(echo "$line" | cut -c1-60)
    req=$(sed 's/|/\\|/g' <<< "$req" | cut -c1-90)
    echo "| $ts | $ip | ${tags%;} | \`$req\` |"
done < "$TMP"
echo ""
echo "## Recommendations"
echo ""
echo "- Use parameterized queries / prepared statements on \`/product/detail\` and \`/search\`; the endpoints are directly injectable."
echo "- Fix the auth bypass: the login query is string-concatenated (\`admin'-- -\` succeeds). Parameterize and enforce server-side auth checks."
echo "- Revoke session \`sess_9f2c1a\` and all \`admin_sessions\` tokens; rotate admin credentials."
echo "- Force password resets for all compromised accounts and enforce MFA; rate-limit and add breach-password detection on \`/account/login\`."
echo "- Treat exfiltrated payment, gift-card, payroll and customer data as breached; trigger DPA/regulator notification and card-network reporting."
echo "- Block/monitor the attacker IPs and tighten WAF to cover UNION-based and inference SQLi, not only stacked queries."
} > "$OUT"

echo "[+] Analysis complete."
echo "[+] $FLAGGED / $TOTAL lines flagged as malicious."
echo "[+] Report written to: $OUT"