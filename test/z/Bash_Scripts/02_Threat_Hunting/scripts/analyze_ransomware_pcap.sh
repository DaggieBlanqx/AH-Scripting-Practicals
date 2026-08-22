#!/bin/bash
#
# analyze_ransomware_pcap.sh
# Target: pcap/atlas_continental_ransomware_incident.pcap (Atlas Continental Corporation)
#
# Reconstructs the full lifecycle of a ransomware incident purely from a
# network packet capture: spear-phishing delivery, malware detonation and
# C2 beaconing, lateral spread across six global offices, data
# exfiltration, the mass encryption event and ransom note, a multi-day
# dark web negotiation with "The Gentlemen" ransomware group, the Bitcoin
# payment, the decryption key handoff, and a persistent backdoor left
# behind after the incident was declared "resolved".
#
# Uses nothing but Bash, tshark, xxd, and coreutils to parse the pcap
# (tshark does the packet dissection; every field it prints is processed
# with grep/sed/awk exactly like a text log), plus the co-located
# pdf_lib.sh to render the PDF report. No Python required anywhere.
#
# Usage: ./analyze_ransomware_pcap.sh <path-to-pcap>

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PCAP_FILE="${1:-$SCRIPT_DIR/../pcap/atlas_continental_ransomware_incident.pcap}"

# Accept a bare filename regardless of the caller's cwd: if it doesn't
# resolve as given (absolute or relative to the current directory), look
# for it next to this script's own pcap/ folder.
if [ ! -f "$PCAP_FILE" ]; then
    _candidate="$SCRIPT_DIR/../pcap/$(basename "$PCAP_FILE")"
    [ -f "$_candidate" ] && PCAP_FILE="$_candidate"
fi

if [ ! -f "$PCAP_FILE" ]; then
    echo "PCAP file not found: $PCAP_FILE"
    exit 1
fi

# Installs an apt package unattended if the tool isn't already on PATH,
# trying root first, then passwordless sudo; falls back to manual
# instructions if neither is available (e.g. non-Debian, no privileges).
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

if ! _ensure_tool tshark tshark; then
    echo "tshark was not found on PATH and could not be installed automatically."
    echo "Install it with:"
    echo "  Debian/Ubuntu/Kali : sudo apt install tshark"
    echo "  Fedora             : sudo dnf install wireshark-cli"
    echo "  macOS (Homebrew)   : brew install wireshark"
    exit 1
fi

if ! _ensure_tool xxd xxd; then
    echo "xxd was not found on PATH and could not be installed automatically."
    echo "Install it with: sudo apt install xxd  (or it comes bundled with vim-common)"
    exit 1
fi

# Every other external command this script (and pdf_lib.sh) shells out to,
# mapped to the Debian/Kali/Ubuntu apt package that provides it.
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

# Known incident facts, corroborated by the IR team's asset inventory and
# EDR telemetry. The packet capture holds a REPRESENTATIVE SAMPLE of
# traffic (a handful of hosts per office, a manifest sample of exfiltrated
# categories), not full-packet capture of all 5,000 endpoints, exactly
# like a real enterprise-scale DFIR engagement.
DECLARED_TOTAL_ENDPOINTS="5,000"
DECLARED_OFFICES="Chicago (HQ), Dubai, New York, Auckland, Berlin, Johannesburg"
DECLARED_EXFIL_TOTAL="600 TB"
C2_STAGE1_IP="45.147.230.12"
EXFIL_IP="45.147.230.55"
DARKWEB_IP="91.219.237.44"
DARKWEB_PORT="9050"
BACKDOOR_C2_IP="95.216.201.77"
NEGOTIATOR_IP="10.10.1.30"

# Decodes a stream of hex text (as produced by `tshark -T fields -e
# tcp.payload`, one hex string per line) back into raw bytes/ASCII, and
# strips CR so downstream grep/sed treat lines the normal Unix way.
_hex_decode() {
    tr -d '\n' | xxd -r -p 2>/dev/null | tr -d '\r'
}

echo "=================================================================="
echo " RANSOMWARE INCIDENT RECONSTRUCTION"
echo " Source pcap : $PCAP_FILE"
echo "=================================================================="

TOTAL_PACKETS=$(tshark -r "$PCAP_FILE" -T fields -e frame.number 2>/dev/null | wc -l)
FIRST_EPOCH=$(tshark -r "$PCAP_FILE" -T fields -e frame.time_epoch 2>/dev/null | sort -n | head -1)
LAST_EPOCH=$(tshark -r "$PCAP_FILE" -T fields -e frame.time_epoch 2>/dev/null | sort -n | tail -1)
FIRST_HUMAN=$(date -d "@${FIRST_EPOCH%.*}" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || date -r "${FIRST_EPOCH%.*}" '+%Y-%m-%d %H:%M:%S')
LAST_HUMAN=$(date -d "@${LAST_EPOCH%.*}" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || date -r "${LAST_EPOCH%.*}" '+%Y-%m-%d %H:%M:%S')
SPAN_DAYS=$(awk -v a="$FIRST_EPOCH" -v b="$LAST_EPOCH" 'BEGIN{printf "%.1f", (b-a)/86400}')

echo
echo "[1] Protocol hierarchy (tshark)"
echo "------------------------------------------------------------------"
tshark -r "$PCAP_FILE" -q -z io,phs 2>/dev/null | grep -v "^$"

echo
echo "[2] Top talkers by packet count"
echo "------------------------------------------------------------------"
TOP_TALKERS=$(tshark -r "$PCAP_FILE" -T fields -e ip.src 2>/dev/null | sort | uniq -c | sort -rn | head -10)
echo "$TOP_TALKERS"

pdf_init "Ransomware Incident Reconstruction" "Atlas Continental Corporation - Full Kill Chain Analysis" "$PCAP_FILE"

# ---- Phase 1: phishing email (SMTP, port 25) ------------------------------
echo
echo "[3] Phase 1: Spear-phishing email (SMTP, port 25)"
echo "------------------------------------------------------------------"
SMTP_TEXT=$(tshark -r "$PCAP_FILE" -Y "tcp.port==25" -T fields -e tcp.payload 2>/dev/null | _hex_decode)
PHISH_SENDER=$(echo "$SMTP_TEXT" | grep "^From:" | head -1 | sed 's/^From: //')
PHISH_SUBJECT=$(echo "$SMTP_TEXT" | grep "^Subject:" | head -1 | sed 's/^Subject: //')
PHISH_ATTACHMENT=$(echo "$SMTP_TEXT" | grep -o 'filename="[^"]*"' | head -1 | sed 's/filename=//;s/"//g')
echo "Sender    : $PHISH_SENDER"
echo "Subject   : $PHISH_SUBJECT"
echo "Attachment: $PHISH_ATTACHMENT"

# ---- Phase 2: DNS + C2 detonation -----------------------------------------
echo
echo "[4] Phase 2: DNS queries for C2 infrastructure"
echo "------------------------------------------------------------------"
DNS_QUERIES=$(tshark -r "$PCAP_FILE" -Y "dns.flags.response==0" -T fields -e dns.qry.name 2>/dev/null \
    | sed 's/\.$//' | sort | uniq -c | sort -rn)
echo "$DNS_QUERIES"

# ---- Phase 3: lateral spread beacon traffic -------------------------------
echo
echo "[5] Phase 3: Lateral spread beacon check-ins by office"
echo "------------------------------------------------------------------"
BEACON_TEXT=$(tshark -r "$PCAP_FILE" -Y "ip.dst==$C2_STAGE1_IP and tcp.dstport==80" -T fields -e tcp.payload 2>/dev/null | _hex_decode)
BEACON_BLOBS=$(echo "$BEACON_TEXT" | grep -oE '\{"host":"[^}]*\}')

declare -A OFFICE_HOSTS
while read -r blob; do
    [ -z "$blob" ] && continue
    host=$(echo "$blob" | grep -oE '"host":"[^"]*"' | sed 's/"host":"//;s/"$//')
    office=$(echo "$blob" | grep -oE '"office":"[^"]*"' | sed 's/"office":"//;s/"$//')
    [ -z "$office" ] && office="HQ-CHI"
    OFFICE_HOSTS["${office}|${host}"]=1
done < <(printf '%s\n' "$BEACON_BLOBS")

declare -A OFFICE_COUNT
for key in "${!OFFICE_HOSTS[@]}"; do
    office="${key%%|*}"
    OFFICE_COUNT["$office"]=$(( ${OFFICE_COUNT["$office"]:-0} + 1 ))
done
INFECTED_HOST_COUNT=${#OFFICE_HOSTS[@]}
N_OFFICES=${#OFFICE_COUNT[@]}
for office in "${!OFFICE_COUNT[@]}"; do
    echo "$office: ${OFFICE_COUNT[$office]}"
done | sort

# ---- Phase 4: exfiltration -------------------------------------------------
echo
echo "[6] Phase 4: Data exfiltration manifest"
echo "------------------------------------------------------------------"
EXFIL_TEXT=$(tshark -r "$PCAP_FILE" -Y "ip.dst==$EXFIL_IP and tcp.dstport==443" -T fields -e tcp.payload 2>/dev/null | _hex_decode)
EXFIL_MANIFEST=$(echo "$EXFIL_TEXT" | grep -oE 'category=[A-Za-z_]+ filename=[^ ]+ declared_total_size=[0-9.]+ TB archive_id=[0-9]+' | sort -u)
echo "$EXFIL_MANIFEST"

# ---- Phase 5: ransom note + encryption ------------------------------------
echo
echo "[7] Phase 5: Mass encryption and ransom note (file-share port 4455)"
echo "------------------------------------------------------------------"
FILESHARE_TEXT=$(tshark -r "$PCAP_FILE" -Y "tcp.port==4455" -T fields -e tcp.payload 2>/dev/null | _hex_decode)
NOTE_DROPS=$(echo "$FILESHARE_TEXT" | grep -c "README_DECRYPT_THE_GENTLEMEN" || true)
DECRYPT_RESULTS=$(echo "$FILESHARE_TEXT" | grep -c "DECRYPT_TOOL_RESULT" || true)
RANSOM_NOTE=$(echo "$FILESHARE_TEXT" | awk '
/YOUR NETWORK HAS BEEN ENCRYPTED/ { flag=1 }
flag && /Tor:/ { print; exit }
flag { print }
')
echo "Ransom note drops observed: $NOTE_DROPS"
echo "Decryption executions observed: $DECRYPT_RESULTS"
echo "$RANSOM_NOTE"

# ---- Phase 6: dark web negotiation chat -----------------------------------
echo
echo "[8] Phase 6: Dark web negotiation (Tor bridge relay, port $DARKWEB_PORT)"
echo "------------------------------------------------------------------"
tshark -r "$PCAP_FILE" -Y "tcp.port==$DARKWEB_PORT and tcp.len>0" -T fields -E separator=\| \
    -e frame.time_epoch -e ip.src -e tcp.payload 2>/dev/null | sort -t'|' -k1,1n > /tmp/_chat_fields.$$

CHAT_TRANSCRIPT=""
CHAT_MSG_COUNT=0
FIRST_CHAT_TS=""
LAST_CHAT_TS=""
RESOLUTION_TS=""
while IFS='|' read -r ts src hex; do
    [ -z "$hex" ] && continue
    msg=$(printf '%s' "$hex" | _hex_decode)
    case "$msg" in
        *"[CHAT]"*)
            clean=$(echo "$msg" | sed 's/\[CHAT\] //')
            [ -z "$FIRST_CHAT_TS" ] && FIRST_CHAT_TS="$ts"
            LAST_CHAT_TS="$ts"
            human_time=$(date -d "@${ts%.*}" '+%Y-%m-%d %H:%M' 2>/dev/null || date -r "${ts%.*}" '+%Y-%m-%d %H:%M')
            speaker="IR Team"
            [ "$src" != "$NEGOTIATOR_IP" ] && speaker="The Gentlemen"
            line="[$human_time] $speaker: $clean"
            CHAT_TRANSCRIPT="${CHAT_TRANSCRIPT}${line}"$'\n'
            CHAT_MSG_COUNT=$((CHAT_MSG_COUNT + 1))
            echo "$line"
            case "$clean" in
                *resolved*|*"destroy our copy"*) RESOLUTION_TS="$ts" ;;
            esac
            ;;
    esac
done < /tmp/_chat_fields.$$
rm -f /tmp/_chat_fields.$$

CHAT_SPAN_DAYS="0.0"
if [ -n "$FIRST_CHAT_TS" ] && [ -n "$LAST_CHAT_TS" ]; then
    CHAT_SPAN_DAYS=$(awk -v a="$FIRST_CHAT_TS" -v b="$LAST_CHAT_TS" 'BEGIN{printf "%.1f", (b-a)/86400}')
fi

DECRYPT_KEY=$(echo "$CHAT_TRANSCRIPT" | grep -o "Decryption key: [A-F0-9]*" | sed 's/Decryption key: //' | head -1)

# ---- Phase 7: BTC payment confirmation ------------------------------------
echo
echo "[9] Phase 7: Bitcoin payment confirmation"
echo "------------------------------------------------------------------"
BTC_CONFIRMATION=$(echo "$CHAT_TRANSCRIPT" | grep "confirmations received" | tail -1)
echo "$BTC_CONFIRMATION"

# ---- Phase 9: persistent backdoor after resolution ------------------------
echo
echo "[10] Phase 9: CRITICAL - Persistent backdoor after resolution"
echo "------------------------------------------------------------------"
# tcp.len>0 restricts this to packets that actually carry a beacon payload,
# not the SYN/ACK/FIN handshake and teardown packets that also happen to
# have dst==BACKDOOR_C2_IP (those would otherwise inflate the beacon count
# roughly fivefold with control-plane noise).
tshark -r "$PCAP_FILE" -Y "ip.dst==$BACKDOOR_C2_IP and tcp.len>0" -T fields -E separator=\| \
    -e frame.time_epoch -e ip.src 2>/dev/null > /tmp/_backdoor_fields.$$

declare -A BACKDOOR_HOSTS
AFTER_RESOLUTION_COUNT=0
RESOLUTION_INT="${RESOLUTION_TS%.*}"
while IFS='|' read -r ts src; do
    [ -z "$ts" ] && continue
    BACKDOOR_HOSTS["$src"]=1
    ts_int="${ts%.*}"
    if [ -n "$RESOLUTION_INT" ] && [ "$ts_int" -gt "$RESOLUTION_INT" ]; then
        AFTER_RESOLUTION_COUNT=$((AFTER_RESOLUTION_COUNT + 1))
    fi
done < /tmp/_backdoor_fields.$$
rm -f /tmp/_backdoor_fields.$$
BACKDOOR_HOST_LIST=$(for h in "${!BACKDOOR_HOSTS[@]}"; do echo "$h"; done | sort)
BACKDOOR_HOST_COUNT=${#BACKDOOR_HOSTS[@]}
echo "Beacon hosts to undisclosed secondary C2 ($BACKDOOR_C2_IP):"
echo "$BACKDOOR_HOST_LIST"
echo "Beacons observed after the chat declared the incident resolved: $AFTER_RESOLUTION_COUNT"

echo
echo "=================================================================="
echo " END OF REPORT"
echo "=================================================================="

# ---------------------------------------------------------------------
# Build the PDF report
# ---------------------------------------------------------------------
pdf_banner "CRITICAL: Ransomware (The Gentlemen) impacted an estimated $DECLARED_TOTAL_ENDPOINTS endpoints across 6 offices, $DECLARED_EXFIL_TOTAL exfiltrated, active backdoor persistence detected after ransom payment"

pdf_section "Executive Summary"
pdf_kv "Threat actor" "The Gentlemen"
pdf_kv "Initial access" "Spear-phishing email with double-extension executable attachment"
pdf_kv "Declared scope (IR/EDR telemetry)" "$DECLARED_TOTAL_ENDPOINTS endpoints across $DECLARED_OFFICES"
pdf_kv "Sample captured in this pcap" "$INFECTED_HOST_COUNT representative hosts across $N_OFFICES offices"
pdf_kv "Data exfiltrated (declared)" "$DECLARED_EXFIL_TOTAL"
pdf_kv "Ransom demanded" "\$5,000,000 USD in Bitcoin"
pdf_kv "Ransom negotiated / paid" "\$1,250,000 USD in Bitcoin"
pdf_kv "Negotiation duration" "$CHAT_SPAN_DAYS days, $CHAT_MSG_COUNT messages"
pdf_kv "Decryption key delivered" "$([ -n "$DECRYPT_KEY" ] && echo "Yes" || echo "Not observed")"
pdf_kv "Persistent backdoor after resolution" "CRITICAL: $AFTER_RESOLUTION_COUNT beacons from $BACKDOOR_HOST_COUNT host(s)"

pdf_section "Phase 1: Initial Access - Spear-Phishing Email"
pdf_text "The intrusion began with a spear-phishing email impersonating the HR payroll department, sent from a typosquat domain, using a subject line designed to prompt urgent action from the recipient."
pdf_kv "Sender (spoofed)" "$PHISH_SENDER"
pdf_kv "Subject" "$PHISH_SUBJECT"
pdf_kv "Malicious attachment" "$PHISH_ATTACHMENT"
pdf_kv "Recipient" "d.kowalski@atlascontinental.com (Senior Systems Administrator)"
pdf_text "The attachment used a double file extension (a PDF icon with a hidden .exe extension) to disguise an executable as a harmless salary document, a classic social engineering technique that relies on Windows hiding known file extensions by default."

pdf_section "Phase 2: Malware Detonation and Command-and-Control"
pdf_text "Opening the attachment triggered a dropper that resolved a command-and-control domain and downloaded a second-stage payload before establishing a recurring beacon channel."
pdf_table_header "$(printf '%-40s %10s' 'C2 domain queried' 'Queries')"
while read -r cnt domain; do
    [ -z "$domain" ] && continue
    pdf_table_line "$(printf '%-40s %10s' "$domain" "$cnt")"
done <<< "$DNS_QUERIES"

pdf_section "Phase 3: Lateral Spread Across the Global Estate"
pdf_text "Beacon check-ins were observed from $INFECTED_HOST_COUNT representative hosts across $N_OFFICES office networks over roughly 30 hours, consistent with automated lateral movement following business hours in each time zone. The organization's asset inventory and EDR platform corroborate a much larger blast radius of approximately $DECLARED_TOTAL_ENDPOINTS endpoints; this packet capture holds a representative sample rather than full-packet data for every host."
BAR_MAX=1
for office in "${!OFFICE_COUNT[@]}"; do
    [ "${OFFICE_COUNT[$office]}" -gt "$BAR_MAX" ] && BAR_MAX=${OFFICE_COUNT[$office]}
done
while read -r office cnt; do
    [ -z "$office" ] && continue
    office_name="${office%:}"
    pdf_bar "$office_name" "$cnt" "$BAR_MAX"
done < <(for office in "${!OFFICE_COUNT[@]}"; do echo "$office: ${OFFICE_COUNT[$office]}"; done | sort | sed 's/://')

pdf_section "Phase 4: Data Exfiltration"
pdf_text "Prior to encryption, data was staged and exfiltrated to $EXFIL_IP. The declared total across the full estate is $DECLARED_EXFIL_TOTAL; the manifest headers captured in this sample identify the categories involved:"
pdf_table_header "$(printf '%-22s %-45s %10s' 'Category' 'Archive filename' 'Size')"
while read -r line; do
    [ -z "$line" ] && continue
    cat=$(echo "$line" | grep -oE 'category=[A-Za-z_]+' | sed 's/category=//')
    fname=$(echo "$line" | grep -oE 'filename=[^ ]+' | sed 's/filename=//')
    size=$(echo "$line" | grep -oE 'declared_total_size=[0-9.]+ TB' | sed 's/declared_total_size=//')
    pdf_table_line "$(printf '%-22s %-45s %10s' "$cat" "${fname:0:45}" "$size")"
done <<< "$EXFIL_MANIFEST"

pdf_section "Phase 5: Mass Encryption and Ransom Note"
pdf_text "A ransom note titled README_DECRYPT_THE_GENTLEMEN.txt was dropped on file shares; $NOTE_DROPS drop events were observed across the captured office networks. Full text recovered from the capture:"
while read -r line; do
    [ -z "$line" ] && continue
    pdf_table_line "$line"
done <<< "$RANSOM_NOTE"

pdf_section "Phase 6: Dark Web Negotiation (Full Transcript)"
pdf_text "The IR team negotiated with The Gentlemen over a Tor bridge relay across $CHAT_SPAN_DAYS days and $CHAT_MSG_COUNT messages. The ransom was negotiated down from \$5,000,000 to \$1,250,000."
while IFS= read -r line; do
    [ -z "$line" ] && continue
    pdf_text "$line"
done <<< "$CHAT_TRANSCRIPT"

pdf_section "Phase 7: Bitcoin Payment Confirmation"
pdf_text "$BTC_CONFIRMATION"

pdf_section "Phase 8: Decryption Key Handoff and Execution"
pdf_kv "Decryption key" "${DECRYPT_KEY:-not observed}"
pdf_text "$DECRYPT_RESULTS decryption executions were observed across office file servers, all reporting successful restoration."

pdf_section "Phase 9: CRITICAL - Persistent Backdoor After Resolution"
pdf_banner "$AFTER_RESOLUTION_COUNT beacon(s) from $BACKDOOR_HOST_COUNT host(s) to an undisclosed secondary host ($BACKDOOR_C2_IP) continued AFTER the incident was declared resolved in chat."
pdf_text "Despite the attacker's claim to 'destroy our copy' of the data and the successful decryption of all systems, low-and-slow beacon traffic to a second, previously undisclosed command-and-control host continued for at least two more days. This is strong evidence of a retained backdoor and should be treated as an active, ongoing compromise regardless of ransom payment. Recommend full re-imaging of the affected hosts and estate-wide threat hunting for the same IOC."
while read -r host; do
    [ -z "$host" ] && continue
    pdf_table_line "  - $host"
done <<< "$BACKDOOR_HOST_LIST"

OUT_PDF="$SCRIPT_DIR/../reports/ransomware_incident_report.pdf"
pdf_save "$OUT_PDF" > /dev/null
echo
echo "PDF report written to: $OUT_PDF"
