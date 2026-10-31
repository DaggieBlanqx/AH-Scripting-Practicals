#!/usr/bin/env bash
#
# sqli_incident_analysis.sh - SQL injection incident analysis for web access logs
#
# Reads an Apache/Nginx "combined" access log (optionally with the extra
# key=value fields an application or WAF appends after the user agent) and
# reconstructs a SQL injection intrusion stage by stage:
#
#   attack tooling -> payload probing (boolean / time / error / UNION)
#   -> blind boolean-based extraction -> schema + table dumps
#   -> authentication bypass -> post-bypass admin abuse + exfiltration
#   -> credential stuffing -> account takeover -> fraudulent orders
#
# Result: a narrative + evidence tables on the console and a Markdown report.
# Pure Bash + POSIX awk + coreutils: no gawk extensions, no bc, no network,
# no external report renderer.
#
# Usage: ./sqli_incident_analysis.sh [options] [LOGFILE]
#
#   LOGFILE       access log to analyse; a .gz file is decompressed in memory.
#                 Defaults to 01_sql_injection_meridian_retail.log, which is
#                 looked up in this folder, ../logs/, ../log_samples/ and the
#                 activity's own logs/ folders, so the script runs from
#                 wherever it was copied to.
#   -o, --out DIR directory for the Markdown report (default: ./reports when
#                 it exists, otherwise ../reports).
#   -q, --quiet   skip the console report; the file is still written.
#   -h, --help    show this help.
#
# Exit status: 0 = no attack indicators, 2 = attack indicators found,
#              1 = usage or input error. Handy for cron/SOAR triage.
#
# The log format is:
#   IP - - [DD/Mon/YYYY:HH:MM:SS +0000] "METHOD /path HTTP/1.1" STATUS BYTES \
#        "REFERER" "USER-AGENT"  key=value ... [marker]
#
# Markers used when present (application/WAF enriched logs):
#   blind_probe, AUTH_BYPASS_SUCCESS, ACCOUNT_TAKEOVER_SUCCESS,
#   EXFIL_CANDIDATE, WAF_BLOCK, SECURITY_ALERT, fraudulent_purchase.
# Lines without markers are classified from payload and behaviour alone.

set -uo pipefail
export LC_ALL=C

PROG=$(basename -- "${BASH_SOURCE[0]}")
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
DEFAULT_LOG="$SCRIPT_DIR/../logs/01_sql_injection_meridian_retail.log"

# Reports land in ./reports when the script sits next to its own run box,
# otherwise in the activity's shared reports/ folder.
if [ -d "$SCRIPT_DIR/reports" ]; then
    OUT_DIR="$SCRIPT_DIR/reports"
else
    OUT_DIR="$SCRIPT_DIR/../reports"
fi
QUIET=0
LOG_ARG=""

usage() {
    cat <<'EOF'
SQL injection incident analysis for Apache/Nginx-style web access logs.

Usage: sqli_incident_analysis.sh [options] [LOGFILE]

  LOGFILE       access log to analyse (.gz is decompressed on the fly).
                Default: 01_sql_injection_meridian_retail.log (looked up in
                this folder, ../logs/, ../log_samples/ and the activity dirs)
  -o, --out DIR directory for the .md report (default: ./reports when it
                exists, otherwise ../reports)
  -q, --quiet   do not print the console report (the file is still written)
  -h, --help    show this help

Exit status: 0 no attack indicators, 2 attack indicators found, 1 error.

What it detects: automated scanning/exploitation tooling, boolean-, time-,
error- and UNION-based SQL injection payloads, stacked queries, blind
boolean extraction campaigns, schema/table dumps, authentication bypass,
post-bypass admin activity and bulk exfiltration, credential stuffing,
account takeover, fraudulent orders, WAF blocks and SOC alerts.
EOF
}

# ---------------------------------------------------------------- arguments
while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help)  usage; exit 0 ;;
        -o|--out)   [ $# -ge 2 ] || { echo "$PROG: -o needs a directory" >&2; exit 1; }
                    OUT_DIR="$2"; shift 2 ;;
        -q|--quiet) QUIET=1; shift ;;
        --)         shift
                    if [ $# -gt 0 ]; then
                        [ -n "$LOG_ARG" ] && {
                            echo "$PROG: only one log file can be analysed per run (got: $LOG_ARG and $1)" >&2
                            exit 1
                        }
                        LOG_ARG="$1"; shift
                    fi
                    [ $# -gt 0 ] && {
                        echo "$PROG: unexpected extra argument: $1 (options must come before --)" >&2
                        exit 1
                    }
                    break ;;
        -*)         echo "$PROG: unknown option: $1 (try --help)" >&2; exit 1 ;;
        *)          [ -n "$LOG_ARG" ] && {
                        echo "$PROG: only one log file can be analysed per run (got: $LOG_ARG and $1)" >&2
                        exit 1
                    }
                    LOG_ARG="$1"; shift ;;
    esac
done

LOG_FILE="${LOG_ARG:-$DEFAULT_LOG}"

# Resolve the log by name in the places it plausibly lives, so the script
# works from any working directory and even when it was copied out of its
# original scripts/ folder (e.g. into a run box of its own).
if [ ! -f "$LOG_FILE" ]; then
    _search_name="$(basename -- "$LOG_FILE")"
    for _dir in "$SCRIPT_DIR" "$SCRIPT_DIR/logs" \
                "$SCRIPT_DIR/../logs" "$SCRIPT_DIR/../log_samples" \
                "$SCRIPT_DIR/../Bash_Scripting/01_Log_Analysis/logs" \
                "$SCRIPT_DIR/../Bash_Scripting/01_Log_Analysis/log_samples" \
                "$SCRIPT_DIR/../../Bash_Scripting/01_Log_Analysis/logs" \
                "$SCRIPT_DIR/../../Bash_Scripting/01_Log_Analysis/log_samples"; do
        [ -f "$_dir/$_search_name" ] && { LOG_FILE="$_dir/$_search_name"; break; }
    done
fi
if [ ! -f "$LOG_FILE" ]; then
    echo "$PROG: log file not found: $LOG_FILE" >&2
    exit 1
fi
LOG_ABS="$LOG_FILE"
if command -v readlink >/dev/null 2>&1; then
    LOG_ABS=$(readlink -f -- "$LOG_FILE" 2>/dev/null) || LOG_ABS="$LOG_FILE"
fi
case "$LOG_ABS" in
    /*) ;;
    *)  LOG_ABS="$(pwd)/$LOG_ABS" ;;
esac

# Paths shown in the console and in the reports are rooted at the repo
# ("/africahackon-course/..."), never at somebody's home directory.
short_path() {
    case "$1" in
        */africahackon-course/*) printf '/africahackon-course/%s\n' "${1#*/africahackon-course/}" ;;
        *)                       printf '%s\n' "$1" ;;
    esac
}
LOG_DISPLAY=$(short_path "$LOG_ABS")

for _tool in awk sed grep sort uniq cut tr wc mktemp date head tail; do
    command -v "$_tool" >/dev/null 2>&1 || {
        echo "$PROG: required tool '$_tool' not found on PATH" >&2
        exit 1
    }
done

TMPD=$(mktemp -d) || { echo "$PROG: cannot create temporary directory" >&2; exit 1; }
trap 'rm -rf "$TMPD"' EXIT

# ------------------------------------------------------- normalise the input
PLAIN="$TMPD/access.log"
case "$LOG_FILE" in
    *.gz|*.tgz)
        gunzip -c -- "$LOG_FILE" > "$PLAIN" 2>/dev/null || {
            echo "$PROG: cannot decompress $LOG_FILE" >&2; exit 1; }
        ;;
    *) cp -- "$LOG_FILE" "$PLAIN" ;;
esac
# A CRLF log (moved off a Windows host) breaks every anchored regex.
if grep -q $'\r' "$PLAIN" 2>/dev/null; then
    tr -d '\r' < "$PLAIN" > "$PLAIN.crlf" && mv -f "$PLAIN.crlf" "$PLAIN"
fi

TSV="$TMPD/classified.tsv"
LIB_AWK="$TMPD/lib.awk"
CLASSIFY_AWK="$TMPD/classify.awk"

# ------------------------------------------------------- shared awk helpers
cat > "$LIB_AWK" <<'AWK'
# Timestamps are fixed-width (14/Jul/2026:00:01:32), so this avoids {n}
# interval expressions and stays portable to mawk.
function is_ts(t) {
    return t ~ /^[0-9][0-9]\/[A-Za-z][A-Za-z][A-Za-z]\/[0-9][0-9][0-9][0-9]:[0-9][0-9]:[0-9][0-9]:[0-9][0-9]$/
}

# Civil date -> epoch seconds (days-from-civil). Valid 1970-2099.
function epoch(ts,  p, d, mo, y, hh, mm, ss, mi, months, k, a, yy, m2, jdn) {
    if (ts == "-" || ts == "") return 0
    split(ts, p, "[/:]")
    d = p[1] + 0; mo = p[2]; y = p[3] + 0
    hh = p[4] + 0; mm = p[5] + 0; ss = p[6] + 0
    months = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec"
    split(months, mi, " ")
    a = 1
    for (k = 1; k <= 12; k++) if (mi[k] == mo) a = k
    y = y + 4800
    yy = y - int((14 - a) / 12)
    m2 = a + 12 * int((14 - a) / 12) - 3
    jdn = d + int((153 * m2 + 2) / 5) + 365 * yy + int(yy / 4) - int(yy / 100) + int(yy / 400) - 32045
    return (jdn - 2440588) * 86400 + hh * 3600 + mm * 60 + ss
}

# Human-readable duration from a number of seconds.
function human(secs) {
    if (secs >= 3600)    return sprintf("%.1f h", secs / 3600)
    else if (secs >= 60) return sprintf("%.1f min", secs / 60)
    else                 return sprintf("%d s", secs)
}

# Short legend label for a detection tag, used by the per-IP rollup.
function label(t) {
    if (t == "TOOL")             return "scan"
    if (t == "SQLI_BOOL")        return "bool"
    if (t == "SQLI_TIME")        return "time"
    if (t == "SQLI_META")        return "schema"
    if (t == "SQLI_UNION")       return "union"
    if (t == "SQLI_STACKED")     return "stacked"
    if (t == "SQLI_BLIND")       return "blind"
    if (t == "AUTH_BYPASS")      return "bypass"
    if (t == "ADMIN")            return "admin"
    if (t == "EXFIL")            return "exfil"
    if (t == "LOGIN_FAIL")       return "loginfail"
    if (t == "ACCOUNT_TAKEOVER") return "ato"
    if (t == "FRAUD")            return "fraud"
    if (t == "WAF_BLOCK")        return "waf"
    if (t == "SOC_ALERT")        return "alert"
    return t
}
AWK

# ------------------------------------------------------ the one-pass parser
# Emits one TSV row per input line:
#   1 client IP ("-" for non-request lines)   7 response bytes
#   2 timestamp DD/Mon/YYYY:HH:MM:SS          8 User-Agent
#   3 epoch seconds (0 if unparsable)         9 tags ",A,B,"
#   4 method                                  10 trailing key=value extras
#   5 raw request path (URL-encoded)          11 percent-decoded request
#   6 status code
cat > "$CLASSIFY_AWK" <<'AWK'
BEGIN { FS = "\t"; OFS = "\t" }
{
    raw = $0
    if (raw == "") next

    ts = "-"
    p = index(raw, "[")
    if (p > 0) { t = substr(raw, p + 1, 20); if (is_ts(t)) ts = t }

    # ---- non-request lines: WAF/SOC console messages, app-level alerts ----
    if (raw !~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ /) {
        tags = ""
        if (raw ~ /SOC_ALERT|SECURITY_ALERT/)       tags = tags ",SOC_ALERT"
        if (raw ~ /WAF_BLOCK|WAF_ALERT/)            tags = tags ",WAF_BLOCK"
        if (raw ~ /AUTH_BYPASS_SUCCESS/)            tags = tags ",AUTH_BYPASS"
        if (raw ~ /ACCOUNT_TAKEOVER_SUCCESS/)       tags = tags ",ACCOUNT_TAKEOVER"
        if (raw ~ /EXFIL_CANDIDATE/)                tags = tags ",EXFIL"
        if (tags != "") tags = tags ","
        print "-", ts, epoch(ts), "-", "-", "-", "-", "-", tags, raw, "-"
        next
    }

    ip = raw
    sub(/[ \t].*$/, "", ip)

    # Split on double quotes:
    #   q[1]=prefix q[2]=request q[3]=" status bytes " q[4]=referer
    #   q[5]=" "    q[6]=User-Agent q[7..]=trailing extras
    nq = split(raw, q, "\"")
    method = "-"; path = "-"; status = "-"; bytes = "-"; ua = "-"; extra = ""
    if (nq >= 3) {
        nr = split(q[2], r, " ")
        if (nr >= 1) method = r[1]
        if (nr >= 2) path   = r[2]
        # first 3-digit code after the request is the status; the number right
        # after it is the response size ("-" when the field is empty)
        if (match(q[3], /[1-5][0-9][0-9]/)) {
            status = substr(q[3], RSTART, 3)
            tail = substr(q[3], RSTART + 3)
            if (match(tail, /[0-9]+/)) bytes = substr(tail, RSTART, RLENGTH)
        }
        if (nq >= 6) ua = q[6]
        for (j = 7; j <= nq; j++) extra = extra (j > 7 ? "\"" : "") q[j]
    }

    # Percent-decode what the detectors need: "OR 1=1" and "UNION SELECT" are
    # sent as %20-encoded bytes and would otherwise never match.
    dec = path " " extra
    gsub(/%20/, " ", dec); gsub(/%09/, " ", dec)
    gsub(/%27/, "'", dec); gsub(/%22/, "\"", dec)
    gsub(/%3B/, ";", dec); gsub(/%3D/, "=", dec)
    gsub(/%2F/, "/", dec); gsub(/%2B/, "+", dec)
    gsub(/%3E/, ">", dec); gsub(/%3C/, "<", dec)

    tags = ""
    ual = tolower(ua)

    # 1. automated scanners and exploitation frameworks
    if (ual ~ /sqlmap|acunetix|nikto|nuclei|dirbuster|gobuster|ffuf|wpscan|masscan|nmap|hydra|wfuzz|commix|havij/)
        tags = tags ",TOOL"

    # 2. injection payload families
    if (dec ~ /UNION (ALL )?SELECT/)                   tags = tags ",SQLI_UNION"
    if (dec ~ /SLEEP *\(|BENCHMARK *\(|PG_SLEEP/)      tags = tags ",SQLI_TIME"
    if (dec ~ /OR 1 *= *1|OR '1' *=' *1|OR 1 *= *'1'/) tags = tags ",SQLI_BOOL"
    if (dec ~ /information_schema|extractvalue|updatexml|@@version|load_file|CONVERT *\( *int/)
        tags = tags ",SQLI_META"
    if (dec ~ /; *(DROP|UPDATE|DELETE|INSERT|ALTER) |DROP TABLE|TRUNCATE TABLE|UPDATE [A-Za-z_]+ SET/)
        tags = tags ",SQLI_STACKED"

    # 3. blind inference: the app/WAF marker, or the payload shape itself
    if (raw ~ /blind_probe/ || dec ~ /ASCII *\( *SUBSTRING|SUBSTRING *\( *\( *SELECT/)
        tags = tags ",SQLI_BLIND"

    # 4. authentication and session events
    if (raw ~ /AUTH_BYPASS_SUCCESS/)                   tags = tags ",AUTH_BYPASS"
    if (raw ~ /ACCOUNT_TAKEOVER_SUCCESS/)              tags = tags ",ACCOUNT_TAKEOVER"
    if (raw ~ /result=DENIED|ACCOUNT_LOCKED/)          tags = tags ",LOGIN_FAIL"

    # 5. post-compromise activity and detection controls
    if (raw ~ /EXFIL_CANDIDATE/)                       tags = tags ",EXFIL"
    if (raw ~ /fraudulent_purchase/)                   tags = tags ",FRAUD"
    if (raw ~ /WAF_BLOCK|WAF_ALERT/)                   tags = tags ",WAF_BLOCK"
    if (raw ~ /SOC_ALERT|SECURITY_ALERT/)              tags = tags ",SOC_ALERT"
    if (path ~ /^\/admin/)                             tags = tags ",ADMIN"

    if (tags != "") tags = tags ","
    print ip, ts, epoch(ts), method, path, status, bytes, ua, tags, extra, dec
}
AWK

# Two aggregations need the shared helpers (label(), human()). mawk treats a
# command-line program as a file operand once -f is used, so they live in
# their own files and are loaded with a second -f.
cat > "$TMPD/attackers.awk" <<'AWK'
BEGIN { FS = "\t"; OFS = "\t" }
$1 != "-" && $9 != "" {
    ip = $1
    cnt[ip]++
    if (!(ip in ft)) ft[ip] = $2
    lt[ip] = $2
    n = split(substr($9, 2, length($9) - 2), t, ",")
    for (k = 1; k <= n; k++) {
        lab = label(t[k])
        if (index(st[ip], "," lab ",") == 0) st[ip] = st[ip] "," lab ","
    }
}
END {
    for (ip in cnt) {
        s = st[ip]; gsub(/^,|,$/, "", s); gsub(/,,/, ",", s)
        printf "%d\t%s\t%s\t%s\t%s\n", cnt[ip], ip, ft[ip], lt[ip], s
    }
}
AWK

cat > "$TMPD/blinddur.awk" <<'AWK'
BEGIN { FS = "\t" }
index($9, ",SQLI_BLIND,") > 0 && $3 > 0 {
    if (!mn || $3 < mn) mn = $3
    if ($3 > mx) mx = $3
}
END {
    if (!mn) { print "n/a\tn/a"; exit }
    printf "%s\t", human(mx - mn)
    if (mx - mn > 0) printf "%.2f probes/s\n", n / (mx - mn)
    else             printf "n/a\n"
}
AWK

awk -f "$LIB_AWK" -f "$CLASSIFY_AWK" "$PLAIN" > "$TSV" || {
    echo "$PROG: failed to parse $LOG_FILE" >&2; exit 1; }

# --------------------------------------------------------------- aggregates
num() { local n; n=$(wc -l 2>/dev/null); n=${n// /}; printf '%s' "${n:-0}"; }

tag_rows()   { awk -F'\t' -v t=",$1," 'index($9, t) > 0' "$TSV"; }
tag_count()  { tag_rows "$1" | num; }
any_sqli()   { awk -F'\t' 'index($9, "SQLI_") > 0' "$TSV"; }
count_rows() { printf '%s\n' "$1" | awk -F'\t' 'NF' | num; }

TOTAL_ROWS=$(num < "$TSV")
META_ROWS=$(awk -F'\t' '$1 == "-"' "$TSV" | num)
REQ_ROWS=$(( TOTAL_ROWS - META_ROWS ))
UNPARSED=$(awk -F'\t' '$1 != "-" && $4 == "-"' "$TSV" | num)

# A log with no recognisable request lines is not a web access log at all
# (syslog, an application audit log, a CSV...). Say so instead of reporting a
# verdict about a format that was never parsed.
HTTP_HITS=$(grep -cE 'HTTP/[0-9]' "$PLAIN" 2>/dev/null || true)
HTTP_HITS=${HTTP_HITS:-0}
if [ "$TOTAL_ROWS" -gt 0 ] && \
   { [ "$REQ_ROWS" -eq 0 ] || [ "$(( HTTP_HITS * 10 ))" -lt "$TOTAL_ROWS" ]; }; then
    echo "$PROG: $LOG_FILE does not look like an HTTP access log" >&2
    echo "        ($REQ_ROWS of $TOTAL_ROWS lines parse as requests, $HTTP_HITS contain an HTTP version token)." >&2
    echo "        Expected the Apache/Nginx combined format:" >&2
    echo '          IP - - [DD/Mon/YYYY:HH:MM:SS +0000] "METHOD /path HTTP/x.y" STATUS BYTES "referer" "user-agent"' >&2
    echo "        No report written." >&2
    exit 1
fi
ATTACK_ROWS=$(awk -F'\t' '$9 != ""' "$TSV" | num)
ATTACK_PCT=$(( ATTACK_ROWS * 100 / (TOTAL_ROWS > 0 ? TOTAL_ROWS : 1) ))

FIRST_TS=$(awk -F'\t' '$2 != "-" {print $2; exit}' "$TSV")
LAST_TS=$(awk -F'\t' '$2 != "-" {t = $2} END {print t}' "$TSV")
FIRST_TS=${FIRST_TS:--}; LAST_TS=${LAST_TS:--}

ALL_CLIENT_IPS=$(awk -F'\t' '$1 != "-" {print $1}' "$TSV" | sort -u | num)
STATUS_DIST=$(awk -F'\t' '$1 != "-" && $6 != "-" {print $6}' "$TSV" \
    | sort | uniq -c | sort -k2,2n | awk '{printf "%s(x%s) ", $2, $1}')

# The application being attacked: the most common referer host in the log.
HOST_LABEL=$(grep -oE 'https?://[^/")]+' "$PLAIN" 2>/dev/null \
    | sed -E 's#^https?://##' \
    | grep -viE '^(www\.)?(google|facebook|bing|twitter|linkedin)\.' \
    | sort | uniq -c | sort -rn | head -1 | awk '{print $2}')
HOST_LABEL=${HOST_LABEL:-the application}

# Attacker inventory: every client IP that triggered at least one tag.
ATK_IP_TABLE=$(awk -f "$LIB_AWK" -f "$TMPD/attackers.awk" "$TSV" | sort -rn -k1,1)
ATK_IPS=$(printf '%s\n' "$ATK_IP_TABLE" | awk -F'\t' 'NF && $2 != "" {print $2}' | tr '\n' ' ')
ATK_IP_COUNT=$(printf '%s\n' "$ATK_IP_TABLE" | awk -F'\t' 'NF && $2 != ""' | num)

# ------------------------------------------------- per-stage statistics
STAGES=(
    "TOOL|Automated scanning / attack tooling"
    "SQLI_BOOL|Boolean-based SQLi payloads"
    "SQLI_TIME|Time-based (SLEEP) probing"
    "SQLI_META|Schema / DB metadata enumeration"
    "SQLI_UNION|UNION-based data extraction"
    "SQLI_STACKED|Stacked / destructive statements"
    "SQLI_BLIND|Blind boolean extraction campaign"
    "AUTH_BYPASS|Authentication bypass"
    "ADMIN|Admin-area requests"
    "EXFIL|Bulk data exfiltration"
    "LOGIN_FAIL|Rejected logins (stuffing)"
    "ACCOUNT_TAKEOVER|Successful account takeover"
    "FRAUD|Fraudulent orders"
    "WAF_BLOCK|WAF blocks"
    "SOC_ALERT|SOC / WAF alerts"
)
declare -a ST_LABEL=() ST_CNT=() ST_FIRST=() ST_LAST=() ST_IPN=()
declare -A CLS_CNT=() CLS_IPN=() CLS_LABEL=()

for _st in "${STAGES[@]}"; do
    _tag=${_st%%|*}
    _desc=${_st#*|}
    _rows=$(tag_rows "$_tag")
    _cnt=$(count_rows "$_rows")
    _ips=$(printf '%s\n' "$_rows" | awk -F'\t' '$1 != "-" {print $1}' | sort -u | tr '\n' ' ')
    _ipn=$(printf '%s\n' "$_ips" | tr ' ' '\n' | grep -c . || true)
    ST_LABEL+=("$_desc")
    ST_CNT+=("$_cnt")
    ST_FIRST+=("$(printf '%s\n' "$_rows" | awk -F'\t' '$2 != "-" {print $2; exit}')")
    ST_LAST+=("$(printf '%s\n' "$_rows" | awk -F'\t' '$2 != "-" {t = $2} END {print t}')")
    ST_IPN+=("${_ipn:-0}")
    case "$_tag" in
        SQLI_*) CLS_CNT[$_tag]="$_cnt"; CLS_LABEL[$_tag]="$_desc"; CLS_IPN[$_tag]="${_ipn:-0}" ;;
    esac
done

# ---------------------------------------------------------- attack surface
SQLI_ROWS=$(any_sqli)
SQLI_TOTAL=$(count_rows "$SQLI_ROWS")
TARGETS=$(printf '%s\n' "$SQLI_ROWS" \
    | awk -F'\t' '{split($5, a, "?"); ep = a[1]; prm = "-";
                   if (length(a) > 1) { split(a[2], b, "="); prm = b[1] }
                   print ep, prm}' \
    | sort | uniq -c | sort -rn)

TOOL_UAS=$(tag_rows TOOL | awk -F'\t' '$8 != "-" {print $8}' | sort | uniq -c | sort -rn)
# "sqlmap/1.7.2#stable", never the bare "sqlmap.org" from its own user agent
TOOL_SIGS=$(printf '%s\n' "$TOOL_UAS" \
    | grep -oiE 'sqlmap(/[^ )",]*)?|acunetix[a-z]*|nikto|nuclei|dirbuster|gobuster|ffuf|wpscan|masscan|hydra|wfuzz|commix' \
    | tr 'A-Z' 'a-z' | sort -u \
    | awk '{base = $0; sub(/\/.*/, "", base)
            if ($0 ~ /\//) versioned[base] = 1
            line[NR] = $0}
           END {for (i = 1; i <= NR; i++) {
                    n = line[i]; b = n; sub(/\/.*/, "", b)
                    if (n !~ /\// && (b in versioned)) continue
                    printf "%s ", n
                }}' | sed 's/ $//')
TOOL_N=$(tag_count TOOL)

# -------------------------------------------------- blind extraction campaign
BLIND_ROWS=$(tag_rows SQLI_BLIND)
BLIND_N=$(count_rows "$BLIND_ROWS")
BLIND_HIT=$(printf '%s\n' "$BLIND_ROWS" | grep -c 'MATCH_CONFIRMED' || true)
BLIND_IPS=$(printf '%s\n' "$BLIND_ROWS" | awk -F'\t' '$1 != "-" {print $1}' \
    | sort | uniq -c | sort -rn)
BLIND_TARGET=$(printf '%s\n' "$BLIND_ROWS" \
    | grep -oE 'SUBSTRING\(\(SELECT [A-Za-z_]+ FROM [A-Za-z_]+' \
    | sed -E 's/SUBSTRING\(\(SELECT ([A-Za-z_]+) FROM ([A-Za-z_]+)/\2.\1/' \
    | sort | uniq -c | sort -rn)
BLIND_AVG=$(printf '%s\n' "$BLIND_ROWS" | grep -oE 'resp_time=[0-9.]+' | cut -d= -f2 \
    | awk '{s += $1; n++} END {if (n) printf "%.2fs", s / n; else printf "n/a"}')
BLIND_DUR=$(printf '%s\n' "$BLIND_ROWS" | awk -f "$LIB_AWK" -f "$TMPD/blinddur.awk" -v n="$BLIND_N")
BLIND_WINDOW=${BLIND_DUR%%$'\t'*}
BLIND_RATE=${BLIND_DUR##*$'\t'}

# ------------------------------------------------------------ UNION dumps
UNION_ROWS=$(tag_rows SQLI_UNION)
UNION_N=$(count_rows "$UNION_ROWS")
DUMP_TABLES=$(printf '%s\n' "$UNION_ROWS" \
    | grep -oiE 'SELECT [A-Za-z_, ]+ FROM [A-Za-z_.]+' \
    | sed -E 's/SELECT (.*) FROM (.*)/\2|\1/' \
    | awk -F'|' '
        {tbl = $1; cols = $2
         gsub(/ *NULL */, " ", cols); gsub(/^ +| +$/, "", cols)
         gsub(/, +,/, ",", cols); gsub(/, *$/, "", cols)
         if (!(tbl in seen)) {seen[tbl] = 1; order[++k] = tbl; first[tbl] = cols}
         if (tbl !~ /information_schema/) dumps[tbl]++}
        END {for (i = 1; i <= k; i++) {t = order[i]
                 if (t ~ /information_schema/) continue
                 printf "%s\t%d\t%s\n", t, dumps[t], first[t]}}' \
    | sort -t$'\t' -k2,2nr)
DUMP_TABLE_N=$(printf '%s\n' "$DUMP_TABLES" | awk -F'\t' 'NF' | num)
SCHEMA_OBJECTS=$(printf '%s\n' "$UNION_ROWS" \
    | grep -oE 'information_schema\.[a-z_]+' | sort -u | paste -sd' ' -)
DUMP_PAGES=$(printf '%s\n' "$UNION_ROWS" | grep -oE 'LIMIT [0-9]+,[0-9]+' \
    | awk '{split($2, a, ","); if (!page) page = a[2]; pages++; maxoff = a[1]}
           END {if (pages) printf "%d dump pages of %d rows (offsets 0..%d)", pages, page, maxoff
                else printf "no paging observed"}')

# -------------------------------------------------------- auth bypass
BYPASS_ROWS=$(tag_rows AUTH_BYPASS)
BYPASS_N=$(count_rows "$BYPASS_ROWS")
BYPASS_IP=$(printf '%s\n' "$BYPASS_ROWS" | awk -F'\t' '$1 != "-" {print $1; exit}')
BYPASS_TS=$(printf '%s\n' "$BYPASS_ROWS" | awk -F'\t' '$2 != "-" {print $2; exit}')
BYPASS_UA=$(printf '%s\n' "$BYPASS_ROWS" | awk -F'\t' '$8 != "-" {print $8; exit}')
BYPASS_PAYLOAD=$(grep 'AUTH_BYPASS_SUCCESS' "$PLAIN" 2>/dev/null \
    | grep -oE "username=[^&]*&password=[^ &]*" | head -1)
BYPASS_REDIRECT=$(grep 'AUTH_BYPASS_SUCCESS' "$PLAIN" 2>/dev/null \
    | grep -oE 'redirect=[^ ]+' | head -1 | cut -d= -f2)
SESSION=$(grep 'AUTH_BYPASS_SUCCESS' "$PLAIN" 2>/dev/null \
    | grep -oE 'session=[A-Za-z0-9_]+' | head -1 | cut -d= -f2)
SESSION=${SESSION:-}

# ------------------------------------------- post-bypass admin + exfiltration
POST_ROWS=""
POST_N=0
if [ -n "$SESSION" ]; then
    POST_ROWS=$(awk -F'\t' -v s="cookie=$SESSION" 'index($10, s) > 0' "$TSV")
    POST_N=$(count_rows "$POST_ROWS")
fi
ADMIN_PATHS=$(printf '%s\n' "$POST_ROWS" | awk -F'\t' '$5 != "-" {split($5, a, "?"); print a[1]}' \
    | sort | uniq -c | sort -rn)
POST_MB=$(printf '%s\n' "$POST_ROWS" | awk -F'\t' '$7 ~ /^[0-9]+$/ {s += $7} END {printf "%.1f", s / 1048576}')

EXFIL_ROWS=$(tag_rows EXFIL)
EXFIL_N=$(count_rows "$EXFIL_ROWS")
EXFIL_BYTES=$(printf '%s\n' "$EXFIL_ROWS" | awk -F'\t' '$7 ~ /^[0-9]+$/ {s += $7} END {print s + 0}')
EXFIL_MB=$(awk -v b="$EXFIL_BYTES" 'BEGIN {printf "%.1f", b / 1048576}')
# keep the full path, including the query string: "?range=all" says a lot
EXFIL_TARGETS=$(printf '%s\n' "$EXFIL_ROWS" \
    | awk -F'\t' '$7 ~ /^[0-9]+$/ {printf "%s\t%d\n", $5, $7}' | sort -k2,2nr)
EXFIL_BIGGEST=$(printf '%s\n' "$EXFIL_TARGETS" | head -1 \
    | awk -F'\t' '{if (NF) printf "%s (%.1f MB)", $1, $2 / 1048576; else printf "n/a"}')

# --------------------------------- credential stuffing / ATO / fraud
LOGIN_ROWS=$(awk -F'\t' 'index($9, ",LOGIN_FAIL,") > 0 || index($9, ",ACCOUNT_TAKEOVER,") > 0' "$TSV")
LOGIN_FAIL_N=$(tag_count LOGIN_FAIL)
ATO_ROWS=$(tag_rows ACCOUNT_TAKEOVER)
ATO_N=$(count_rows "$ATO_ROWS")
ATO_ACCOUNTS=$(printf '%s\n' "$ATO_ROWS" \
    | grep -oE 'username=[^& ]+' | sed 's/^username=//' | sort -u)
ATO_IP_TABLE=$(printf '%s\n' "$LOGIN_ROWS" | awk -F'\t' '
    $1 != "-" {
        if (index($9, ",ACCOUNT_TAKEOVER,") > 0) ok[$1]++; else bad[$1]++
        ips[$1] = 1
    }
    END {for (ip in ips) printf "%s\t%d\t%d\n", ip, ok[ip] + 0, bad[ip] + 0}' \
    | sort -rn -k2,2 -k3,3)
ATO_IP_N=$(printf '%s\n' "$ATO_IP_TABLE" | awk -F'\t' 'NF' | num)
ATO_SUBNET=$(printf '%s\n' "$ATO_IP_TABLE" | awk -F'\t' '{print $1}' \
    | awk -F. '{print $1"."$2"."$3".0/24"}' | sort -u | head -3 | paste -sd' ' -)
LOGIN_UA=$(printf '%s\n' "$LOGIN_ROWS" | awk -F'\t' '$8 != "-" {print $8}' | sort | uniq -c | sort -rn | head -3)

# Every POST to the login endpoint, marker or not: a burst from one /24 is
# the stuffing fingerprint even in a log with no application enrichment.
LOGIN_ALL=$(awk -F'\t' '$1 != "-" && $4 == "POST" && index($5, "/account/login") == 1' "$TSV")
LOGIN_N=$(count_rows "$LOGIN_ALL")
LOGIN_ALL_IP_TABLE=$(printf '%s\n' "$LOGIN_ALL" | awk -F'\t' '
    $1 != "-" {c[$1]++; if (index($9, ",ACCOUNT_TAKEOVER,") > 0) ok[$1]++}
    END {for (ip in c) printf "%d\t%d\t%s\n", c[ip], ok[ip] + 0, ip}' \
    | sort -rn -k1,1 | head -8)

FRAUD_ROWS=$(tag_rows FRAUD)
FRAUD_N=$(count_rows "$FRAUD_ROWS")
FRAUD_ORDERS=$(printf '%s\n' "$FRAUD_ROWS" | awk -F'\t' '
    $10 ~ /account=/ {
        acct = "-"; ph = "-"
        n = split($10, f, " ")
        for (i = 1; i <= n; i++) {
            if (f[i] ~ /^account=/) {acct = f[i]; sub(/^account=/, "", acct)}
            if (f[i] ~ /^phone=/)   {ph = f[i]; sub(/^phone=/, "", ph)}
        }
        printf "%s\t%s\t%s\n", $2, acct, ph
    }' | sort -u)

# ------------------------------------------------------------ WAF + SOC
WAF_ROWS=$(tag_rows WAF_BLOCK)
WAF_N=$(count_rows "$WAF_ROWS")
WAF_RULES=$(printf '%s\n' "$WAF_ROWS" | awk -F'\t' '{print $10}' \
    | grep -oE 'rule=[A-Za-z0-9_]+' | sed 's/rule=//' | sort | uniq -c | sort -rn)
SOC_ROWS=$(tag_rows SOC_ALERT)
SOC_N=$(count_rows "$SOC_ROWS")
SOC_MSG=$(printf '%s\n' "$SOC_ROWS" | grep -oE 'msg="[^"]*"' | sed 's/^msg=//' | head -2)

# ------------------------------------------------------------ verdict
if [ "$ATTACK_ROWS" -eq 0 ]; then
    SEVERITY="NONE"
elif [ "$(( BYPASS_N + EXFIL_N + ATO_N + FRAUD_N ))" -gt 0 ]; then
    SEVERITY="CRITICAL"
elif [ "$SQLI_TOTAL" -gt 0 ] || [ "$WAF_N" -gt 0 ]; then
    SEVERITY="HIGH"
else
    SEVERITY="MEDIUM"
fi
case "$SEVERITY" in
    CRITICAL) HEADLINE="Exploit succeeded - credentials stolen, login bypassed, data exfiltrated" ;;
    HIGH)     HEADLINE="Active exploitation - injection confirmed, no evidence of data theft" ;;
    MEDIUM)   HEADLINE="Reconnaissance only - tooling and probing without a confirmed hit" ;;
    *)        HEADLINE="No SQL injection indicators found" ;;
esac

# ------------------------------------------------------------------ colours
if [ -t 1 ]; then
    B=$'\033[1m'; R=$'\033[31m'; G=$'\033[32m'; Y=$'\033[33m'
    C=$'\033[36m'; N=$'\033[0m'
else
    B=""; R=""; G=""; Y=""; C=""; N=""
fi

rule() { printf '%s\n' "------------------------------------------------------------------"; }
kv()   { printf '  %-30s %s\n' "$1" "$2"; }

TS_COMPACT=$(date -u '+%Y%m%d_%H%M%S')
mkdir -p "$OUT_DIR" 2>/dev/null || {
    echo "$PROG: cannot create output directory: $OUT_DIR" >&2; exit 1; }
OUT_ABS="$OUT_DIR"
if command -v readlink >/dev/null 2>&1; then
    OUT_ABS=$(readlink -f -- "$OUT_DIR" 2>/dev/null) || OUT_ABS="$OUT_DIR"
fi
REPORT_MD="$OUT_ABS/sqli_incident_${TS_COMPACT}.md"

# =========================================================== console report
if [ "$QUIET" -eq 0 ]; then
    printf '\n%s\n' "${B}==================================================================${N}"
    printf '%s\n'   "${B} SQL INJECTION INCIDENT ANALYSIS${N}"
    printf '%s\n'   "${B}==================================================================${N}"
    kv "Source log"    "$LOG_DISPLAY"
    kv "Target host"   "$HOST_LABEL"
    kv "Generated"     "$(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    kv "Log lines"     "$TOTAL_ROWS  (requests $REQ_ROWS, meta $META_ROWS, unparsable $UNPARSED)"
    kv "Time range"    "$FIRST_TS -> $LAST_TS"
    kv "Client IPs"    "$ALL_CLIENT_IPS unique"
    kv "Status codes"  "$STATUS_DIST"
    kv "Flagged rows"  "$ATTACK_ROWS ($ATTACK_PCT% of the log)"
    kv "Attacker IPs"  "$ATK_IP_COUNT${ATK_IPS:+ -> $ATK_IPS}"
    case "$SEVERITY" in
        CRITICAL) printf '  %-30s %s\n' "Verdict" "${R}${B}CRITICAL${N} - $HEADLINE" ;;
        HIGH)     printf '  %-30s %s\n' "Verdict" "${Y}${B}HIGH${N} - $HEADLINE" ;;
        MEDIUM)   printf '  %-30s %s\n' "Verdict" "${Y}MEDIUM${N} - $HEADLINE" ;;
        *)        printf '  %-30s %s\n' "Verdict" "${G}NONE${N} - $HEADLINE" ;;
    esac

    printf '\n'; rule; printf '%s\n' "${B}[1] Attack surface - endpoints carrying payloads${N}"; rule
    printf '  %s requests over %s endpoint/parameter pairs:\n' \
        "$SQLI_TOTAL" "$(printf '%s\n' "$TARGETS" | awk 'NF' | num)"
    printf '%s\n' "$TARGETS" | head -6 | while read -r c ep prm; do
        printf '    %-30s  param %-12s %6s requests\n' "$ep" "$prm" "$c"
    done

    printf '\n'; rule; printf '%s\n' "${B}[2] Automated tooling${N}"; rule
    if [ -n "$TOOL_UAS" ]; then
        printf '%s\n' "$TOOL_UAS" | while read -r c ua; do
            printf '    %4s x  %s\n' "$c" "$ua"
        done
    else
        printf '    none\n'
    fi

    printf '\n'; rule; printf '%s\n' "${B}[3] Attack stages and timeline${N}"; rule
    printf '  %-38s %7s  %-20s %-20s %s\n' "STAGE" "EVENTS" "FIRST SEEN" "LAST SEEN" "ACTORS"
    for i in "${!ST_LABEL[@]}"; do
        [ "${ST_CNT[$i]}" = "0" ] && continue
        _actors="${ST_IPN[$i]}"
        [ "$_actors" = "0" ] && _actors="-"
        printf '  %-38s %7s  %-20s %-20s %s\n' \
            "${ST_LABEL[$i]}" "${ST_CNT[$i]}" "${ST_FIRST[$i]:--}" "${ST_LAST[$i]:--}" "$_actors"
    done

    printf '\n'; rule; printf '%s\n' "${B}[4] Blind boolean-based extraction${N}"; rule
    if [ "$BLIND_N" -gt 0 ]; then
        kv "Probes"             "$BLIND_N over $BLIND_WINDOW ($BLIND_RATE)"
        kv "Confirmed matches"  "$BLIND_HIT character matches"
        kv "Mean response time" "$BLIND_AVG"
        kv "Source IPs"         "$(printf '%s\n' "$BLIND_IPS" | awk '{printf "%s(%s) ", $2, $1}')"
        kv "Column targeted"    "$(printf '%s\n' "$BLIND_TARGET" | awk '{printf "%s ", $2}')"
        printf '    The attacker asked yes/no questions ("is character N of the admin hash\n'
        printf '    greater than 55?") and read the answer from the response shape. No error\n'
        printf '    page, no stack trace -- which is why blind injection hides so well.\n'
    else
        printf '    none detected\n'
    fi

    printf '\n'; rule; printf '%s\n' "${B}[5] UNION-based dumps${N}"; rule
    if [ "$UNION_N" -gt 0 ]; then
        kv "UNION requests" "$UNION_N"
        kv "Schema probing" "${SCHEMA_OBJECTS:-none}"
        kv "Paging"         "$DUMP_PAGES"
        printf '\n  %-26s %6s  %s\n' "TABLE" "DUMPS" "COLUMNS PULLED"
        printf '%s\n' "$DUMP_TABLES" | while IFS=$'\t' read -r t c cols; do
            [ -z "${t:-}" ] && continue
            printf '  %-26s %6s  %s\n' "$t" "$c" "$cols"
        done
    else
        printf '    none detected\n'
    fi

    printf '\n'; rule; printf '%s\n' "${B}[6] Authentication bypass${N}"; rule
    if [ "$BYPASS_N" -gt 0 ]; then
        kv "Events"         "$BYPASS_N"
        kv "Attacker IP"    "$BYPASS_IP"
        kv "Time"           "$BYPASS_TS"
        kv "Client"         "${BYPASS_UA:-n/a}"
        kv "Injected login" "${BYPASS_PAYLOAD:-n/a}"
        kv "Session issued" "${SESSION:-n/a}"
        kv "Redirected to"  "${BYPASS_REDIRECT:-n/a}"
        printf '    The username was concatenated into the login query, so the payload\n'
        printf '    closed the string and commented out the password check.\n'
    else
        printf '    none detected\n'
    fi

    printf '\n'; rule; printf '%s\n' "${B}[7] Post-bypass admin activity and exfiltration${N}"; rule
    if [ -n "$SESSION" ]; then
        kv "Requests on session" "${SESSION}: $POST_N (${POST_MB} MB)"
    fi
    if [ "$POST_N" -gt 0 ]; then
        printf '  Endpoints touched:\n'
        printf '%s\n' "$ADMIN_PATHS" | head -12 | while read -r c p; do
            printf '    %4s x  %s\n' "$c" "$p"
        done
    fi
    if [ "$EXFIL_N" -gt 0 ]; then
        kv "Exfiltration" "$EXFIL_N requests, ${EXFIL_MB} MB (${EXFIL_BYTES} bytes)"
        kv "Largest pull" "$EXFIL_BIGGEST"
        printf '  Full-table exports and numbered backup chunks, not browsing: customer,\n'
        printf '  order, payment, gift-card and payroll data left the network.\n'
    elif [ -n "$SESSION" ]; then
        printf '    no bulk export traffic tied to the session\n'
    fi

    printf '\n'; rule; printf '%s\n' "${B}[8] Credential stuffing -> takeover -> fraud${N}"; rule
    if [ "$LOGIN_N" -gt 0 ]; then
        kv "Login POSTs"  "$LOGIN_N (rejected $LOGIN_FAIL_N / succeeded $ATO_N)"
        kv "Stuffing IPs" "$ATO_IP_N across ${ATO_SUBNET:-n/a}"
        kv "Client"       "$(printf '%s\n' "$LOGIN_UA" | awk '{printf "%s ", $2}')"
        printf '\n  %-18s %8s %9s\n' "IP" "ATTEMPTS" "SUCCEEDED"
        printf '%s\n' "$LOGIN_ALL_IP_TABLE" | while IFS=$'\t' read -r a s ip; do
            [ -z "${ip:-}" ] && continue
            printf '  %-18s %8s %9s\n' "$ip" "$a" "$s"
        done
        if [ "$ATO_N" -gt 0 ]; then
            printf '\n  Compromised customer accounts (%s):\n' "$ATO_N"
            printf '%s\n' "$ATO_ACCOUNTS" | while read -r a; do
                [ -n "$a" ] && printf '    - %s\n' "$a"
            done
        fi
        if [ "$FRAUD_N" -gt 0 ]; then
            printf '\n  Fraudulent orders (%s):\n' "$FRAUD_N"
            printf '%s\n' "$FRAUD_ORDERS" | while IFS=$'\t' read -r ts acct ph; do
                [ -n "${acct:-}" ] && printf '    - %s  %s  (phone %s)\n' "$ts" "$acct" "$ph"
            done
        fi
    else
        printf '    none detected\n'
    fi

    printf '\n'; rule; printf '%s\n' "${B}[9] Detection controls${N}"; rule
    kv "WAF blocks" "$WAF_N"
    printf '%s\n' "$WAF_RULES" | while read -r c r; do
        [ -n "${r:-}" ] && printf '    %4s x  rule=%s\n' "$c" "$r"
    done
    kv "SOC alerts" "$SOC_N"
    printf '%s\n' "$SOC_MSG" | while read -r m; do
        [ -n "$m" ] && printf '    %s\n' "$m"
    done
    if [ "$WAF_N" -gt 0 ] && [ "$(( UNION_N + BLIND_N + BYPASS_N ))" -gt 0 ]; then
        printf '    The WAF stopped stacked DROP/UPDATE statements but not UNION dumps,\n'
        printf '    blind inference or the login bypass: a partial rule set buys less time\n'
        printf '    than it looks like it does.\n'
    fi

    printf '\n'; rule; printf '%s\n' "${B}[10] Attacker IP rollup${N}"; rule
    printf '  %-18s %7s  %-20s %-20s %s\n' "IP" "ROWS" "FIRST" "LAST" "STAGES"
    printf '%s\n' "$ATK_IP_TABLE" | head -12 | while IFS=$'\t' read -r c ip f l s; do
        [ -z "${ip:-}" ] && continue
        printf '  %-18s %7s  %-20s %-20s %s\n' "$ip" "$c" "$f" "$l" "$s"
    done
fi

# ============================================================ markdown report
md_esc() { printf '%s' "${1//|/\\|}"; }

{
printf '# SQL Injection Incident Report\n\n'
printf '**Target:** `%s`  \n' "$HOST_LABEL"
printf '**Source log:** `%s`  \n' "$LOG_DISPLAY"
printf '**Generated:** %s  \n' "$(date -u '+%Y-%m-%d %H:%M:%S UTC')"
printf '**Producer:** `%s` (automated Bash analysis)  \n' "$PROG"
printf '**Severity:** **%s** - %s\n\n' "$SEVERITY" "$HEADLINE"

printf '## Executive summary\n\n'
# The summary is assembled from what the log actually contains, so a clean log
# is never handed the narrative of someone else's breach.
if [ "$SEVERITY" = "NONE" ]; then
    printf 'No SQL injection indicators were found in this log. %s requests from %s client IPs\n' "$REQ_ROWS" "$ALL_CLIENT_IPS"
    printf 'were classified for tooling, payload families, blind inference, schema or table\n'
    printf 'dumps, login bypass, bulk export and stuffing bursts; none matched. Ordinary traffic\n'
    printf 'to `%s` dominates the window, which is what a clean baseline looks like.\n\n' "$HOST_LABEL"
else
    printf 'The access log for `%s` covers %s requests from %s client IPs; %s rows (%s%%)\n' \
        "$HOST_LABEL" "$REQ_ROWS" "$ALL_CLIENT_IPS" "$ATTACK_ROWS" "$ATTACK_PCT"
    printf 'carry attack indicators, from %s distinct addresses:\n\n' "$ATK_IP_COUNT"
    _bullet=""
    [ "$TOOL_N" -gt 0 ]     && _bullet="${_bullet}Automated tooling (\`${TOOL_SIGS:-unknown}\`) scanned the application over $TOOL_N requests. "
    [ "$SQLI_TOTAL" -gt 0 ] && _bullet="${_bullet}$SQLI_TOTAL requests carried injection payloads across $(printf '%s\n' "$TARGETS" | awk 'NF' | num) endpoint/parameter pairs. "
    [ -n "$_bullet" ]       && printf -- '- %s\n' "$_bullet"
    _bullet=""
    [ "$BLIND_N" -gt 0 ]      && _bullet="${_bullet}$BLIND_N blind boolean probes over $BLIND_WINDOW pulled column values out one character at a time. "
    [ "$DUMP_TABLE_N" -gt 0 ] && _bullet="${_bullet}UNION queries paged out $DUMP_TABLE_N tables ($(printf '%s\n' "$DUMP_TABLES" | awk -F'\t' 'NF {printf "%s, ", $1}' | sed 's/, $//')). "
    [ -n "$_bullet" ]         && printf -- '- %s\n' "$_bullet"
    _bullet=""
    [ "$BYPASS_N" -gt 0 ] && _bullet="${_bullet}The login form was bypassed with an injected username from $BYPASS_IP, yielding session \`${SESSION:-n/a}\`. "
    [ "$EXFIL_N" -gt 0 ]  && _bullet="${_bullet}$EXFIL_MB MB then left through that session in $EXFIL_N bulk export/backup requests. "
    [ "$ATO_N" -gt 0 ]    && _bullet="${_bullet}$ATO_N customer accounts were taken over with the harvested credentials and $FRAUD_N fraudulent orders were placed. "
    [ -n "$_bullet" ]     && printf -- '- %s\n' "$_bullet"
    printf '\n'
fi

printf '| Metric | Value |\n|---|---|\n'
printf '| Log lines / requests | %s / %s |\n' "$TOTAL_ROWS" "$REQ_ROWS"
printf '| Time range | %s to %s |\n' "$FIRST_TS" "$LAST_TS"
printf '| Rows with attack indicators | %s (%s%%) |\n' "$ATTACK_ROWS" "$ATTACK_PCT"
printf '| Attacker IPs | %s |\n' "$ATK_IP_COUNT"
printf '| SQLi-carrying requests | %s |\n' "$SQLI_TOTAL"
printf '| Tables dumped | %s |\n' "$DUMP_TABLE_N"
printf '| Blind probes | %s |\n' "$BLIND_N"
printf '| Auth bypass / accounts taken over | %s / %s |\n' "$BYPASS_N" "$ATO_N"
printf '| Data exfiltrated | %s MB in %s requests |\n' "$EXFIL_MB" "$EXFIL_N"
printf '| WAF blocks / SOC alerts | %s / %s |\n\n' "$WAF_N" "$SOC_N"

printf '## Attack timeline\n\n'
printf '| Stage | Events | First seen | Last seen | Actors |\n|---|---:|---|---|---:|\n'
for i in "${!ST_LABEL[@]}"; do
    [ "${ST_CNT[$i]}" = "0" ] && continue
    printf '| %s | %s | %s | %s | %s |\n' \
        "${ST_LABEL[$i]}" "${ST_CNT[$i]}" "${ST_FIRST[$i]:--}" "${ST_LAST[$i]:--}" "${ST_IPN[$i]}"
done

printf '\n## 1. Attack surface\n\n'
printf 'Every endpoint/parameter pair that carried an injection payload:\n\n'
printf '| Endpoint | Parameter | Requests |\n|---|---|---:|\n'
printf '%s\n' "$TARGETS" | awk 'NF' | while read -r c ep prm; do
    printf '| `%s` | `%s` | %s |\n' "$ep" "$prm" "$c"
done

printf '\n## 2. Automated tooling\n\n'
if [ -n "$TOOL_UAS" ]; then
    printf '| Requests | User-Agent |\n|---:|---|\n'
    printf '%s\n' "$TOOL_UAS" | while read -r c ua; do
        [ -n "${ua:-}" ] && printf '| %s | `%s` |\n' "$c" "$(md_esc "$ua")"
    done
else
    printf '_No attack-tool user agents observed._\n'
fi

printf '\n## 3. SQL injection payload classes\n\n'
printf '| Class | Requests | Distinct IPs |\n|---|---:|---:|\n'
for _tag in SQLI_BOOL SQLI_TIME SQLI_META SQLI_UNION SQLI_STACKED SQLI_BLIND; do
    printf '| %s | %s | %s |\n' "${CLS_LABEL[$_tag]}" "${CLS_CNT[$_tag]:-0}" "${CLS_IPN[$_tag]:-0}"
done

printf '\n## 4. Blind boolean-based extraction\n\n'
if [ "$BLIND_N" -gt 0 ]; then
    printf '| Field | Value |\n|---|---|\n'
    printf '| Probes | %s |\n' "$BLIND_N"
    printf '| Rate | %s over %s |\n' "$BLIND_RATE" "$BLIND_WINDOW"
    printf '| Confirmed character matches | %s |\n' "$BLIND_HIT"
    printf '| Mean response time | %s |\n' "$BLIND_AVG"
    printf '| Source IPs | %s |\n' "$(printf '%s\n' "$BLIND_IPS" | awk '{printf "`%s` (%s)  ", $2, $1}')"
    printf '| Data targeted | %s |\n\n' "$(printf '%s\n' "$BLIND_TARGET" | awk '{printf "`%s` (%s probes)  ", $2, $1}')"
    printf 'The attacker asked the database yes/no questions - "is character N of the admin\n'
    printf 'password hash greater than 55?", "does it equal 0x62?" - and inferred the answer\n'
    printf 'from the response shape rather than from any error. Roughly %s probes decoded a\n' "$BLIND_N"
    printf 'credential column a character at a time. This is the quietest stage in the log:\n'
    printf 'every request returned 200 with a plausible response size.\n'
else
    printf '_No blind extraction detected._\n'
fi

printf '\n## 5. UNION-based dumps\n\n'
if [ "$UNION_N" -gt 0 ]; then
    printf '%s UNION requests; schema objects probed: `%s`; paging: %s.\n\n' \
        "$UNION_N" "${SCHEMA_OBJECTS:-none}" "$DUMP_PAGES"
    printf '| Table | Dump requests | Columns exfiltrated |\n|---|---:|---|\n'
    printf '%s\n' "$DUMP_TABLES" | while IFS=$'\t' read -r t c cols; do
        [ -n "${t:-}" ] && printf '| `%s` | %s | `%s` |\n' "$t" "$c" "$(md_esc "$cols")"
    done
    printf '\nThe attacker first sent `UNION SELECT NULL` probes to count columns, then replaced\n'
    printf 'each `NULL` with a column of interest and paged through the table 50 rows at a time.\n'
    printf 'Column-count probing is the signature to alert on: a normal customer never sends\n'
    printf '`UNION SELECT` anywhere near a product page.\n'
else
    printf '_No UNION dumps detected._\n'
fi

printf '\n## 6. Authentication bypass\n\n'
if [ "$BYPASS_N" -gt 0 ]; then
    printf '| Field | Value |\n|---|---|\n'
    printf '| Timestamp | %s |\n' "$BYPASS_TS"
    printf '| Source IP | `%s` |\n' "$BYPASS_IP"
    printf '| Client | `%s` |\n' "$(md_esc "${BYPASS_UA:-n/a}")"
    printf '| Injected login | `%s` |\n' "$(md_esc "${BYPASS_PAYLOAD:-n/a}")"
    printf '| Password field | never evaluated - commented out by the payload |\n'
    printf '| Session granted | `%s` |\n' "${SESSION:-n/a}"
    printf '| Redirect | `%s` |\n\n' "${BYPASS_REDIRECT:-n/a}"
    printf 'The login query was built by string concatenation, so the username payload closed\n'
    printf 'the literal and commented out the password comparison. The application answered 302\n'
    printf 'to the admin dashboard: from its point of view, an administrator had logged in.\n'
else
    printf '_No authentication bypass detected._\n'
fi

printf '\n## 7. Post-bypass admin activity\n\n'
if [ "$POST_N" -gt 0 ]; then
    printf '%s requests carried the hijacked session `%s`:\n\n' "$POST_N" "$SESSION"
    printf '| Requests | Path |\n|---:|---|\n'
    printf '%s\n' "$ADMIN_PATHS" | while read -r c p; do
        [ -n "${p:-}" ] && printf '| %s | `%s` |\n' "$c" "$p"
    done
else
    printf '_No requests tied to a hijacked session._\n'
fi

printf '\n## 8. Data exfiltration\n\n'
if [ "$EXFIL_N" -gt 0 ]; then
    printf '**%s MB** (%s bytes) left the network in %s requests.\n\n' \
        "$EXFIL_MB" "$EXFIL_BYTES" "$EXFIL_N"
    printf '| Size | Path |\n|---:|---|\n'
    printf '%s\n' "$EXFIL_TARGETS" | head -20 \
        | awk -F'\t' '{printf "| %.2f MB | `%s` |\n", $2 / 1048576, $1}'
    printf '\nEvery transfer is a complete export or a numbered backup chunk: this was a copy,\n'
    printf 'not a browse. Treat all of these data sets as breached.\n'
else
    printf '_No bulk exfiltration detected._\n'
fi

printf '\n## 9. Credential stuffing and account takeover\n\n'
if [ "$LOGIN_N" -gt 0 ]; then
    printf '| Metric | Value |\n|---|---|\n'
    printf '| Login POSTs | %s |\n' "$LOGIN_N"
    printf '| Rejected | %s |\n' "$LOGIN_FAIL_N"
    printf '| Succeeded (ATO) | %s |\n' "$ATO_N"
    printf '| Stuffing IPs | %s |\n' "$ATO_IP_N"
    printf '| Clusters | `%s` |\n' "${ATO_SUBNET:-n/a}"
    printf '| Client | `%s` |\n\n' "$(printf '%s\n' "$LOGIN_UA" | awk '{printf "%s ", $2}')"
    printf '| IP | Attempts | Succeeded |\n|---|---:|---:|\n'
    printf '%s\n' "$LOGIN_ALL_IP_TABLE" | while IFS=$'\t' read -r a s ip; do
        [ -n "${ip:-}" ] && printf '| `%s` | %s | %s |\n' "$ip" "$a" "$s"
    done
    if [ "$ATO_N" -gt 0 ]; then
        printf '\n**Compromised customer accounts (%s):**\n\n' "$ATO_N"
        printf '%s\n' "$ATO_ACCOUNTS" | while read -r a; do
            [ -n "$a" ] && printf -- '- `%s`\n' "$a"
        done
    fi
    if [ "$FRAUD_N" -gt 0 ]; then
        printf '\n**Fraudulent orders (%s):**\n\n' "$FRAUD_N"
        printf '| Time | Account | Phone |\n|---|---|---|\n'
        printf '%s\n' "$FRAUD_ORDERS" | while IFS=$'\t' read -r ts acct ph; do
            [ -n "${acct:-}" ] && printf '| %s | `%s` | `%s` |\n' "$ts" "$acct" "$ph"
        done
    fi
else
    printf '_No credential stuffing or account takeover detected._\n'
fi

printf '\n## 10. Detection controls\n\n'
printf '| Control | Events | Detail |\n|---|---:|---|\n'
printf '| WAF blocks | %s | %s |\n' "$WAF_N" \
    "$(printf '%s\n' "$WAF_RULES" | awk '{printf "%s x rule=%s; ", $1, $2}')"
printf '| SOC alerts | %s | %s |\n\n' "$SOC_N" "$(md_esc "$(printf '%s\n' "$SOC_MSG" | head -1)")"
if [ "$WAF_N" -gt 0 ] && [ "$(( UNION_N + BLIND_N + BYPASS_N ))" -gt 0 ]; then
    printf 'The WAF only stopped stacked `DROP`/`UPDATE` statements. UNION dumps, blind\n'
    printf 'inference and the login bypass passed straight through, so the block list bought\n'
    printf 'less time than it looked like it did. Coverage has to follow the payload families\n'
    printf 'actually in use, not just the loudest one.\n'
fi

printf '\n## 11. Indicators of compromise\n\n'
printf '| Type | Value |\n|---|---|\n'
printf '| Attacking IPs | %s |\n' "$(printf '%s\n' "$ATK_IP_TABLE" | awk -F'\t' 'NF && $2 != "" {printf "`%s` ", $2}')"
printf '| Hijacked session | `%s` |\n' "${SESSION:-n/a}"
printf '| Tooling signatures | `%s` |\n' "${TOOL_SIGS:-none}"
printf '| Injection points | %s |\n' "$(printf '%s\n' "$TARGETS" | awk 'NF {printf "`%s?%s` ", $2, $3}' | cut -c1-160)"
printf '| Dumped tables | %s |\n' "$(printf '%s\n' "$DUMP_TABLES" | awk -F'\t' 'NF {printf "`%s` ", $1}')"
printf '| Compromised accounts | %s |\n' "$(printf '%s\n' "$ATO_ACCOUNTS" | awk 'NF {printf "`%s` ", $0}' | cut -c1-200)"
printf '| Exfil endpoints | %s |\n\n' "$(printf '%s\n' "$EXFIL_TARGETS" | awk -F'\t' 'NR<=5 {printf "`%s` ", $1}')"

printf '\n## 12. Root cause and remediation\n\n'
if [ "$SEVERITY" = "NONE" ]; then
    printf '**Root cause.** None demonstrated in this window: no payload reached a SQL sink.\n'
    printf 'That is a statement about this log, not a guarantee about the application - keep the\n'
    printf 'controls that produce it and re-run this analyser on a wider window after any change.\n\n'
    printf '| Priority | Action |\n|---|---|\n'
    printf '| P1 | Keep every query parameterized; never build SQL by concatenation, so this stays true. |\n'
    printf '| P1 | Run the web application under a least-privilege database account (no schema, no credential or payroll tables). |\n'
    printf '| P2 | Keep the WAF rule set current, and alert on `sqlmap`/`Acunetix` user agents and on %%27 in query strings. |\n'
    printf '| P2 | Baseline this log so future deviations (new payload families, new /24s hitting login) stand out automatically. |\n'
else
printf '**Root cause.** User input reached SQL string concatenation on two surfaces: the read\n'
printf 'path (`/product/detail?id=` and `/search?q=`) and the authentication path\n'
printf '(`/account/login`). Because the query text changed with attacker input, one injection\n'
printf 'point cascaded into schema enumeration, credential theft and a full login bypass\n'
printf '(OWASP Top 10 A03:2021 - Injection). The exported backups and payroll data show the\n'
printf 'database account also had far more read access than a storefront needs.\n\n'
printf '| Priority | Action |\n|---|---|\n'
printf '| P0 | Revoke session `%s`, rotate all admin credentials, force resets on the %s compromised customer accounts. |\n' "${SESSION:-n/a}" "$ATO_N"
printf '| P0 | Treat the %s dumped tables as breached: regulator and card-network notification, customer notice, forensic image of the database host. |\n' "$DUMP_TABLE_N"
printf '| P1 | Replace every string-built query with parameterized statements (or an ORM that enforces them) on `/product/detail`, `/search` and `/account/login`. |\n'
printf '| P1 | Give the web application a least-privilege database account: no schema access, no `UNION`-readable credential or payroll tables, no backup privileges. |\n'
printf '| P1 | Add MFA and rate limiting to login plus breached-password detection; alert on login bursts from one /24. |\n'
printf '| P2 | Extend WAF rules to UNION, blind inference and auth-bypass payloads; alert on any request whose query string contains SQL keywords. |\n'
printf '| P2 | Block the attacker IPs and alert on `sqlmap`/`Acunetix` user agents, `%%27` in query strings and sequential `product/detail?id=` enumeration. |\n'
printf '| P2 | Require re-authentication for `/admin/*` and treat bulk export/backup endpoints as high-risk actions needing approval and logging. |\n'
fi
} > "$REPORT_MD" || {
    echo "$PROG: failed to write $REPORT_MD" >&2; exit 1; }

# ------------------------------------------------------------------- finish
if [ "$QUIET" -eq 0 ]; then
    printf '\n%s\n' "${C}Report written${N}"
    kv "Markdown" "$(short_path "$REPORT_MD")"
    printf '\n'
fi

if [ "$ATTACK_ROWS" -gt 0 ]; then exit 2; else exit 0; fi
