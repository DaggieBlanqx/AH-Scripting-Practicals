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
