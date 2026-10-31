#!/usr/bin/env bash
#
# md2pdf.sh - convert Markdown to PDF, re-usably and without dependencies.
#
# Renders a practical Markdown subset into a paginated PDF: headings,
# paragraphs (with **bold**, *italic* and `code` inline), bullet and ordered
# lists, fenced code blocks, block quotes, tables, horizontal rules and links.
#
# Everything happens in one Bash + awk + coreutils pass: no pandoc, no LaTeX,
# no Python, no Ghostscript, no network. Classic PDF 1.4 syntax is written
# directly, one uncompressed content stream per page, so the result opens in
# any viewer and the file stays readable in a text editor.
#
# Usage: ./md2pdf.sh [options] FILE.md [FILE2.md ...]
#
#   -o, --out FILE      output PDF (default: first input with a .pdf suffix)
#   -t, --title TEXT    document title for continuation-page headers
#                       (default: the first H1 in the document)
#       --subtitle TEXT subtitle printed under the first-page heading rule
#   -s, --size SIZE     a4 (default) or letter
#       --no-header     do not print the title on continuation pages
#       --no-footer     do not print page numbers
#   -h, --help          show this help
#
# Multiple inputs are concatenated in the order given, so a set of reports can
# be bound into one PDF. "FILE.md" may be "-" to read standard input.
#
# Exit status: 0 = PDF written, 1 = usage or input error.

set -uo pipefail
export LC_ALL=C

PROG=$(basename -- "${BASH_SOURCE[0]}")
OUT=""
TITLE=""
SUBTITLE=""
SIZE="a4"
HEADER=1
FOOTER=1
INPUTS=()

usage() {
    cat <<'EOF'
Convert Markdown to a paginated PDF with no external dependencies.

Usage: md2pdf.sh [options] FILE.md [FILE2.md ...]

  -o, --out FILE      output PDF (default: first input with a .pdf suffix)
  -t, --title TEXT    document title for continuation-page headers
                      (default: the first H1 in the document)
      --subtitle TEXT subtitle printed under the first-page heading rule
  -s, --size SIZE     a4 (default) or letter
      --no-header     do not print the title on continuation pages
      --no-footer     do not print page numbers
  -h, --help          show this help

Multiple inputs are concatenated in the order given. FILE.md may be "-" to
read standard input.

Exit status: 0 PDF written, 1 usage or input error.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help)   usage; exit 0 ;;
        -o|--out)    [ $# -ge 2 ] || { echo "$PROG: -o needs a file" >&2; exit 1; }
                     OUT="$2"; shift 2 ;;
        -t|--title)  [ $# -ge 2 ] || { echo "$PROG: -t needs text" >&2; exit 1; }
                     TITLE="$2"; shift 2 ;;
        --subtitle)  [ $# -ge 2 ] || { echo "$PROG: --subtitle needs text" >&2; exit 1; }
                     SUBTITLE="$2"; shift 2 ;;
        -s|--size)   [ $# -ge 2 ] || { echo "$PROG: -s needs a4 or letter" >&2; exit 1; }
                     SIZE="$2"; shift 2 ;;
        --no-header) HEADER=0; shift ;;
        --no-footer) FOOTER=0; shift ;;
        --)          shift
                     while [ $# -gt 0 ]; do INPUTS+=("$1"); shift; done ;;
        -)           INPUTS+=("-"); shift ;;
        -*)          echo "$PROG: unknown option: $1 (try --help)" >&2; exit 1 ;;
        *)           INPUTS+=("$1"); shift ;;
    esac
done

[ ${#INPUTS[@]} -gt 0 ] || { echo "$PROG: no input file (try --help)" >&2; exit 1; }

case "$SIZE" in
    a4|A4)         PW=595; PH=842 ;;
    letter|Letter) PW=612; PH=792 ;;
    *)             echo "$PROG: unknown page size '$SIZE' (use a4 or letter)" >&2; exit 1 ;;
esac

for _tool in awk sed grep head wc mktemp mv cat; do
    command -v "$_tool" >/dev/null 2>&1 || {
        echo "$PROG: required tool '$_tool' not found on PATH" >&2; exit 1; }
done

TMPD=$(mktemp -d) || { echo "$PROG: cannot create temporary directory" >&2; exit 1; }
trap 'rm -rf "$TMPD"' EXIT

# ---- gather input ---------------------------------------------------------
MD="$TMPD/input.md"
: > "$MD"
FIRST_INPUT=""
for _f in "${INPUTS[@]}"; do
    [ -z "$FIRST_INPUT" ] && FIRST_INPUT="$_f"
    if [ "$_f" = "-" ]; then
        cat >> "$MD"
        printf '\n\n' >> "$MD"
    elif [ -f "$_f" ]; then
        cat -- "$_f" >> "$MD"
        printf '\n\n' >> "$MD"
    else
        echo "$PROG: cannot read input: $_f" >&2
        exit 1
    fi
done

# blank-only input is a usage error, not an empty PDF
if ! grep -q '[^[:space:]]' "$MD" 2>/dev/null; then
    echo "$PROG: input has no content, nothing to convert" >&2
    exit 1
fi

if [ -z "$OUT" ]; then
    case "$FIRST_INPUT" in
        -)            OUT="stdin.pdf" ;;
        *.md)         OUT="${FIRST_INPUT%.md}.pdf" ;;
        *.markdown)   OUT="${FIRST_INPUT%.markdown}.pdf" ;;
        *)            OUT="$FIRST_INPUT.pdf" ;;
    esac
fi

OUT_DIR=$(dirname -- "$OUT")
[ -d "$OUT_DIR" ] || mkdir -p "$OUT_DIR" 2>/dev/null || {
    echo "$PROG: cannot create output directory: $OUT_DIR" >&2; exit 1; }

# ---- normalise the text ---------------------------------------------------
# The PDF text operators only carry bytes 0x20-0x7e safely, so typographic
# characters are transliterated first, then anything left is dropped by awk.
CLEAN_MD="$TMPD/clean.md"
sed -e 's/—/-/g'  -e 's/–/-/g'  -e 's/…/.../g' \
    -e 's/“/"/g'  -e 's/”/"/g'  -e "s/‘/'/g" -e "s/’/'/g" \
    -e 's/•/-/g'  -e 's/·/-/g'  -e 's/→/->/g' -e 's/←/<-/g' \
    -e 's/≥/>=/g' -e 's/≤/<=/g' -e 's/≠/!=/g' \
    -e 's/&amp;/\&/g' -e 's/&lt;/</g' -e 's/&gt;/>/g' \
    -e 's/&quot;/"/g' -e "s/&#39;/'/g" -e 's/&nbsp;/ /g' \
    "$MD" > "$CLEAN_MD" || { echo "$PROG: failed to pre-process input" >&2; exit 1; }

PAGES_FILE="$TMPD/pages"
TMP_PDF="$TMPD/out.pdf"

# ---- the renderer ---------------------------------------------------------
cat > "$TMPD/md2pdf.awk" <<'AWK'
# ---------------------------------------------------------------------------
# Markdown -> PDF engine. Reads the transliterated markdown and writes a
# complete PDF to stdout. Line breaking is measured with average glyph widths
# (crude but stable); drawing a line is one text object, so the viewer's own
# glyph advances keep mixed fonts from overlapping.
# ---------------------------------------------------------------------------

function num(x) { return sprintf("%.2f", x) }

function esc(s) {
    gsub(/\\/, "\\\\", s)
    gsub(/\(/, "\\(", s)
    gsub(/\)/, "\\)", s)
    return s
}

function add(s) { C[page] = C[page] s "\n" }

function txt(x, yy, f, sz, col, s) {
    if (s == "") return
    add("BT /" f " " num(sz) " Tf " col " rg 1 0 0 1 " num(x) " " num(yy) " Tm (" esc(s) ") Tj ET")
}

function rect(x, yy, w, h, col) {
    add(col " rg " num(x) " " num(yy) " " num(w) " " num(h) " re f")
}

function hline(x1, yy, x2, col, wid) {
    add(col " RG " num(wid) " w " num(x1) " " num(yy) " m " num(x2) " " num(yy) " l S")
}

function vline(x1, y1, y2, col, wid) {
    add(col " RG " num(wid) " w " num(x1) " " num(y1) " m " num(x1) " " num(y2) " l S")
}

function cw(f, sz) {
    if (f == "F3") return sz * 0.6
    if (f == "F2") return sz * 0.56
    return sz * 0.5
}

function tw(f, sz, s) { return length(s) * cw(f, sz) }

# ---- text sanitation ------------------------------------------------------
function ascii_only(s,   i, n, ch, out) {
    out = ""
    n = length(s)
    for (i = 1; i <= n; i++) {
        ch = substr(s, i, 1)
        if (ch == "\t") out = out "    "
        else if (index(PRINTABLE, ch) > 0) out = out ch
    }
    return out
}

function trim(s,   t) { t = s; sub(/^[ \t]+/, "", t); sub(/[ \t]+$/, "", t); return t }

function collapse(s) { gsub(/  +/, " ", s); return s }

# [text](url) and ![alt](src) collapse to their visible text. Hand-rolled
# because mawk has no back-references in gsub().
function strip_links(s,   a, b, c, pre, mid, rest, i) {
    while ((a = index(s, "](")) > 0) {
        c = index(substr(s, a + 2), ")")
        if (c == 0) break
        b = 0
        for (i = a - 1; i >= 1; i--) {
            if (substr(s, i, 1) == "[") { b = i; break }
        }
        if (b == 0) break
        pre = substr(s, 1, b - 1)
        mid = substr(s, b + 1, a - b - 1)
        rest = substr(s, a + 2 + c)
        if (substr(pre, length(pre), 1) == "!") pre = substr(pre, 1, length(pre) - 1)
        s = pre mid rest
    }
    return s
}

function strip_md_links(s) {
    s = strip_links(s)
    gsub(/<[^>]*>/, "", s)
    return s
}

function plain(s,   t) {
    t = s
    t = strip_links(t)
    gsub(/<[^>]*>/, "", t)
    gsub(/`/, "", t)
    gsub(/\*\*/, "", t)
    gsub(/\*/, "", t)
    t = ascii_only(t)
    t = trim(t)
    return t
}

# ---- inline runs (bold / italic / code) -----------------------------------
function push_run(t, f) {
    if (t == "") return
    TRn++
    TRt[TRn] = t
    TRf[TRn] = f
}

function curf(b, i) {
    if (b) return "F2"
    if (i) return "F4"
    return "F1"
}

function tokenize(s,   i, n, ch, two, chunk, bold, ital, code) {
    TRn = 0; bold = 0; ital = 0; code = 0; chunk = ""
    n = length(s)
    for (i = 1; i <= n; i++) {
        ch = substr(s, i, 1)
        if (code) {
            if (ch == "`") { push_run(chunk, "F3"); chunk = ""; code = 0 }
            else chunk = chunk ch
            continue
        }
        if (ch == "`") { push_run(chunk, curf(bold, ital)); chunk = ""; code = 1; continue }
        two = substr(s, i, 2)
        if (two == "**") {
            push_run(chunk, curf(bold, ital)); chunk = ""
            bold = 1 - bold; i++; continue
        }
        if (ch == "*") {
            push_run(chunk, curf(bold, ital)); chunk = ""
            ital = 1 - ital; continue
        }
        chunk = chunk ch
    }
    push_run(chunk, curf(bold, ital))
}

# ---- wrapping -------------------------------------------------------------
# Words are whitespace-delimited and may span several font runs, so
# "(`sqlmap`)" stays one word instead of becoming "( code )".
function wrap_rich(s, width, sz,   k, j, m, f, t, p, seg, wn, cur, lw, w, sp, nw, flat, maxch, piece, base, cut, ch) {
    tokenize(s)

    wn = 1
    WS[1] = 0
    for (k = 1; k <= TRn; k++) {
        f = TRf[k]
        t = TRt[k]
        while (t != "") {
            if (substr(t, 1, 1) == " ") {
                while (substr(t, 1, 1) == " ") t = substr(t, 2)
                if (WS[wn] > 0) { wn++; WS[wn] = 0 }
                continue
            }
            p = index(t, " ")
            if (p > 0) { seg = substr(t, 1, p - 1); t = substr(t, p) }
            else { seg = t; t = "" }
            WS[wn]++
            WST[wn, WS[wn]] = seg
            WSF[wn, WS[wn]] = f
        }
    }
    if (wn > 0 && WS[wn] == 0) wn--
    if (wn == 0) { WFNL = 0; return 0 }

    # measure; anything wider than the measure is flattened and hard-cut
    nw = 0
    for (j = 1; j <= wn; j++) {
        w = 0
        for (m = 1; m <= WS[j]; m++) w += tw(WSF[j, m], sz, WST[j, m])
        if (w <= width) {
            nw++
            WS2[nw] = WS[j]
            WW2[nw] = w
            for (m = 1; m <= WS[j]; m++) {
                WST2[nw, m] = WST[j, m]
                WSF2[nw, m] = WSF[j, m]
            }
        } else {
            flat = ""
            base = WSF[j, 1]
            for (m = 1; m <= WS[j]; m++) flat = flat WST[j, m]
            maxch = int(width / cw(base, sz))
            if (maxch < 1) maxch = 1
            while (flat != "") {
                cut = maxch
                if (length(flat) > maxch) {
                    for (m = maxch; m > 1 && m > maxch - 16; m--) {
                        ch = substr(flat, m, 1)
                        if (ch == "/" || ch == "-" || ch == "_" || ch == "?" || ch == "&" || ch == ".") {
                            cut = m
                            break
                        }
                    }
                }
                piece = substr(flat, 1, cut)
                flat = substr(flat, cut + 1)
                nw++
                WS2[nw] = 1
                WST2[nw, 1] = piece
                WSF2[nw, 1] = base
                WW2[nw] = tw(base, sz, piece)
            }
        }
    }

    WFNL = 0
    cur = 0
    lw = 0
    for (j = 1; j <= nw; j++) {
        w = WW2[j]
        sp = tw("F1", sz, " ")
        if (cur == 0 || lw + sp + w > width) {
            cur++
            LNPT[cur] = 0
            lw = 0
            sp = 0
        }
        LNPT[cur]++
        LW[cur, LNPT[cur]] = j
        lw = lw + sp + w
    }
    WFNL = cur
    return WFNL
}

function draw_line_rich(i, x0, sz, col,   k, j, m, f, t, s) {
    s = "BT " col " rg 1 0 0 1 " num(x0) " " num(y) " Tm"
    for (k = 1; k <= LNPT[i]; k++) {
        j = LW[i, k]
        for (m = 1; m <= WS2[j]; m++) {
            f = WSF2[j, m]
            t = WST2[j, m]
            s = s " /" f " " num(sz) " Tf (" esc(t) ") Tj"
        }
        if (k < LNPT[i]) s = s " /" f " " num(sz) " Tf ( ) Tj"
    }
    s = s " ET"
    add(s)
}

# Single-font wrapping (headings, subtitles): fills PL[] and returns the count.
function wrap_plain(s, width, sz, font,   n, words, i, ln, ww, cch) {
    PN = 0
    n = split(trim(s), words, " ")
    ln = ""
    for (i = 1; i <= n; i++) {
        ww = words[i]
        if (ww == "") continue
        while (tw(font, sz, ww) > width) {
            cch = int(width / cw(font, sz))
            if (cch < 1) cch = 1
            if (ln != "") { PN++; PL[PN] = ln; ln = "" }
            PN++
            PL[PN] = substr(ww, 1, cch)
            ww = substr(ww, cch + 1)
        }
        if (ln == "") ln = ww
        else if (tw(font, sz, ln " " ww) <= width) ln = ln " " ww
        else { PN++; PL[PN] = ln; ln = ww }
    }
    if (ln != "") { PN++; PL[PN] = ln }
    return PN
}

# ---- page control ---------------------------------------------------------
function newpage() {
    page++
    C[page] = ""
    y = top
    draw_header()
}

function need(h) { if (y - h < bottom) newpage() }

function draw_header() {
    if (!hdr || page == 1 || doc_title == "") return
    txt(left, ph - margin + 11, "F1", 8, GREY, doc_title)
    hline(left, ph - margin + 5, right, RULE, 0.5)
}

# ---- block renderers ------------------------------------------------------
function heading(level, s,   n, sz, lead, before, after, col, i) {
    s = plain(s)
    if (s == "") return
    if (level == 1) {
        if (doc_title == "" && !title_set) { doc_title = s; title_set = 1 }
        sz = 19; lead = 23; before = 4; after = 10; col = NAVY
    } else if (level == 2) {
        sz = 14.5; lead = 19; before = 13; after = 5; col = NAVY
    } else if (level == 3) {
        sz = 12; lead = 16; before = 10; after = 4; col = BLACK
    } else {
        sz = 10.8; lead = 14; before = 8; after = 3; col = BLACK
    }
    n = wrap_plain(s, usable, sz, "F2")
    if (n == 0) return
    need(before + lead * n + after + 2 * LEAD)
    y -= before
    for (i = 1; i <= n; i++) {
        y -= lead
        txt(left, y, "F2", sz, col, PL[i])
    }
    y -= after
    if (level == 1) {
        hline(left, y, right, NAVY, 0.8)
        y -= 8
        if (subtitle != "") {
            n = wrap_plain(subtitle, usable, 10.5, "F1")
            for (i = 1; i <= n; i++) {
                need(15); y -= 15
                txt(left, y, "F1", 10.5, GREY, PL[i])
            }
            y -= 6
        }
    }
}

function paragraph(s,   nl, i) {
    if (trim(s) == "") return
    s = collapse(ascii_only(trim(strip_md_links(s))))
    nl = wrap_rich(s, usable, BODY)
    if (nl == 0) return
    need(LEAD)
    y -= 3
    for (i = 1; i <= nl; i++) {
        need(LEAD)
        y -= LEAD
        draw_line_rich(i, left, BODY, BLACK)
    }
    y -= 4
}

# Wrapped continuation with no block spacing: used for explicit line breaks.
function paragraph_tight(s,   nl, i) {
    if (trim(s) == "") return
    s = collapse(ascii_only(trim(strip_md_links(s))))
    nl = wrap_rich(s, usable, BODY)
    if (nl == 0) return
    for (i = 1; i <= nl; i++) {
        need(LEAD)
        y -= LEAD
        draw_line_rich(i, left, BODY, BLACK)
    }
}

function bullet_item(s, marker,   nl, numw, bx, i) {
    s = collapse(ascii_only(trim(strip_md_links(s))))
    if (s == "") return
    numw = (marker == "") ? 0 : tw("F1", BODY, marker) + 3
    bx = left + numw
    nl = wrap_rich(s, usable - numw - 12, BODY)
    if (nl == 0) return
    y -= 1
    for (i = 1; i <= nl; i++) {
        need(LEAD)
        y -= LEAD
        if (i == 1) {
            if (marker == "") rect(left + 1.5, y + 3.2, 2.6, 2.6, NAVY)
            else txt(left, y, "F1", BODY, GREY, marker)
        }
        draw_line_rich(i, bx + 12, BODY, BLACK)
    }
    y -= 2
}

function quote_item(s,   nl, i) {
    s = collapse(ascii_only(trim(strip_md_links(s))))
    if (s == "") return
    nl = wrap_rich(s, usable - 20, BODY)
    if (nl == 0) return
    y -= 1
    for (i = 1; i <= nl; i++) {
        need(LEAD)
        y -= LEAD
        rect(left + 2, y - 2.5, 2.2, LEAD - 2, NAVY)
        draw_line_rich(i, left + 14, BODY, GREY)
    }
    y -= 3
}

function code_flush(   i, total, maxch, h, lineh, cl, k) {
    if (CODEn == 0) return
    lineh = 11.5
    maxch = int((usable - 18) / cw("F3", 8.5))
    if (maxch < 10) maxch = 10
    total = 0
    for (i = 1; i <= CODEn; i++) {
        cl = ascii_only(CODE[i])
        gsub(/\t/, "    ", cl)
        k = 1
        while (1) {
            total++
            OUTL[total] = substr(cl, k, maxch)
            k += maxch
            if (k > length(cl)) break
        }
    }
    h = total * lineh + 10
    if (h <= (top - bottom)) {
        need(h)
        rect(left, y - h + 6, usable, h, LIGHT)
        vline(left, y - h + 6, y + 4, RULE, 1.2)
    }
    for (i = 1; i <= total; i++) {
        need(lineh)
        if (h > (top - bottom)) {
            rect(left, y - lineh + 2, usable, lineh, LIGHT)
            vline(left, y - lineh + 2, y + 2, RULE, 1.2)
        }
        y -= lineh
        txt(left + 7, y + 1, "F3", 8.5, BLACK, OUTL[i])
    }
    y -= 8
    CODEn = 0
}

function table_flush(   r, c, i, nrows, ncols, n, total, cwpt, xpos, row, maxch, hh, cell, hpage, sumw) {
    if (TBLn == 0) return
    nrows = 0
    ncols = 0
    for (r = 1; r <= TBLn; r++) {
        row = trim(TBL[r])
        sub(/^\|/, "", row)
        sub(/\|$/, "", row)
        if (row ~ /^[-: |]+$/) continue
        nrows++
        n = split(row, CELL, "|")
        if (n > ncols) ncols = n
        for (c = 1; c <= n; c++) {
            TCELL[nrows, c] = trim(CELL[c])
            if (length(plain(TCELL[nrows, c])) > MAXLEN[c])
                MAXLEN[c] = length(plain(TCELL[nrows, c]))
        }
    }
    TBLn = 0
    if (nrows == 0 || ncols == 0) return

    cwpt = cw("F3", 8.5)
    total = 0
    for (c = 1; c <= ncols; c++) {
        if (MAXLEN[c] > 70) MAXLEN[c] = 70
        if (MAXLEN[c] < 4) MAXLEN[c] = 4
        total += MAXLEN[c]
    }
    for (c = 1; c <= ncols; c++) COLW[c] = (usable - 6) * MAXLEN[c] / total
    # if a slim column was widened to the minimum, trim the widest ones back
    sumw = 0
    for (c = 1; c <= ncols; c++) {
        if (COLW[c] < 5 * cwpt) COLW[c] = 5 * cwpt
        sumw += COLW[c]
    }
    if (sumw > usable - 6) {
        for (c = 1; c <= ncols; c++) COLW[c] = COLW[c] * (usable - 6) / sumw
    }

    y -= 4
    hpage = 0
    for (r = 1; r <= nrows; r++) {
        hh = 14
        need(hh + 2)
        xpos = left + 2
        if (r == 1) {
            hpage = page
            rect(left - 1, y - hh + 3.5, usable, hh, NAVY)
            for (c = 1; c <= ncols; c++) {
                cell = plain(TCELL[r, c])
                maxch = int((COLW[c] - 4) / cwpt)
                if (maxch < 1) maxch = 1
                if (length(cell) > maxch) cell = substr(cell, 1, maxch)
                txt(xpos + 2, y - hh + 8, "F2", 8.5, WHITE, cell)
                xpos += COLW[c]
            }
        } else {
            if (page != hpage) {
                # repeat the header after a page break
                xpos = left + 2
                rect(left - 1, y - hh + 3.5, usable, hh, NAVY)
                for (c = 1; c <= ncols; c++) {
                    cell = plain(TCELL[1, c])
                    maxch = int((COLW[c] - 4) / cwpt)
                    if (maxch < 1) maxch = 1
                    if (length(cell) > maxch) cell = substr(cell, 1, maxch)
                    txt(xpos + 2, y - hh + 8, "F2", 8.5, WHITE, cell)
                    xpos += COLW[c]
                }
                y -= hh
                need(hh + 2)
                hpage = page
                xpos = left + 2
            }
            for (c = 1; c <= ncols; c++) {
                cell = plain(TCELL[r, c])
                maxch = int((COLW[c] - 4) / cwpt)
                if (maxch < 1) maxch = 1
                if (length(cell) > maxch) cell = substr(cell, 1, maxch - 2) ".."
                if (cell != "") txt(xpos + 2, y - hh + 8, "F3", 8.5, BLACK, cell)
                xpos += COLW[c]
            }
            hline(left - 1, y - hh + 2, right - 1, RULE, 0.4)
        }
        y -= hh
    }
    y -= 6
}

function hr() {
    need(12)
    y -= 7
    hline(left, y, right, RULE, 0.8)
    y -= 7
}

function footer(i,   s, x) {
    if (!ftr) return
    s = "Page " i
    x = (pw - tw("F1", 8, s)) / 2
    C[i] = C[i] "BT /F1 8 Tf " GREY " rg 1 0 0 1 " num(x) " " num(margin + 12) " Tm (" s ") Tj ET\n"
}

# ---- document -------------------------------------------------------------
BEGIN {
    if (pw == 0) pw = 595
    if (ph == 0) ph = 842
    if (margin == 0) margin = 54
    top = ph - margin - 10
    bottom = margin + 30
    left = margin
    right = pw - margin
    usable = right - left
    NAVY  = "0.09 0.16 0.25"
    GREY  = "0.42 0.45 0.50"
    LIGHT = "0.955 0.960 0.970"
    RULE  = "0.78 0.80 0.84"
    BLACK = "0 0 0"
    WHITE = "1 1 1"
    BODY = 10.5
    LEAD = 14.5
    PRINTABLE = ""
    for (i = 32; i <= 126; i++) PRINTABLE = PRINTABLE sprintf("%c", i)
    hdr = hdr + 0
    ftr = ftr + 0
    page = 1
    C[1] = ""
    y = top
    doc_title = ttl
    if (doc_title != "") title_set = 1
    pending = ""
    in_code = 0
    CODEn = 0
    TBLn = 0
}

{
    line = $0
    sub(/\r$/, "", line)

    if (line ~ /^[ \t]*$/) {
        if (pending != "") { paragraph(pending); pending = "" }
        if (TBLn > 0) table_flush()
        next
    }

    # a leading --- is YAML front matter only if the next line is "key:"
    if (NR == 1 && line == "---") { fm_check = 1; next }
    if (fm_check) {
        fm_check = 0
        if (line ~ /^[A-Za-z_][A-Za-z0-9_-]*:/) { in_fm = 1; next }
    }
    if (in_fm) { if (line == "---") in_fm = 0; next }

    # fenced code
    if (line ~ /^[ \t]*```/) {
        if (in_code) { code_flush(); in_code = 0 }
        else { in_code = 1; CODEn = 0 }
        next
    }
    if (in_code) { CODEn++; CODE[CODEn] = line; next }

    # table rows
    if (line ~ /^[ \t]*\|/) {
        if (pending != "") { paragraph(pending); pending = "" }
        TBLn++
        TBL[TBLn] = line
        next
    }
    if (TBLn > 0) table_flush()

    # html comments
    if (line ~ /^[ \t]*<!--/) {
        if (index(line, "-->") == 0) in_comment = 1
        next
    }
    if (in_comment) {
        if (index(line, "-->") > 0) in_comment = 0
        next
    }

    # horizontal rule
    if (line ~ /^[ \t]*---+[ \t]*$/ || line ~ /^[ \t]*\*\*\*+[ \t]*$/ || line ~ /^[ \t]*___+[ \t]*$/) {
        if (pending != "") { paragraph(pending); pending = "" }
        hr()
        next
    }

    # heading: count the leading hashes (no interval expressions in mawk)
    h = 0
    while (substr(line, h + 1, 1) == "#") h++
    if (h > 0 && h < 7 && (substr(line, h + 1, 1) == " " || length(line) == h)) {
        if (pending != "") { paragraph(pending); pending = "" }
        heading(h, substr(line, h + 1))
        next
    }

    # block quote
    if (line ~ /^[ \t]*>/) {
        if (pending != "") { paragraph(pending); pending = "" }
        q = line
        sub(/^[ \t]*> ?/, "", q)
        quote_item(q)
        next
    }

    # bullet list
    if (line ~ /^[ \t]*[-*+][ \t]/) {
        if (pending != "") { paragraph(pending); pending = "" }
        it = line
        sub(/^[ \t]*[-*+][ \t]+/, "", it)
        bullet_item(it, "")
        next
    }

    # ordered list
    if (line ~ /^[ \t]*[0-9]+[.)][ \t]/) {
        if (pending != "") { paragraph(pending); pending = "" }
        onum = line
        sub(/[ \t].*$/, "", onum)
        sub(/^[ \t]*/, "", onum)
        it = line
        sub(/^[ \t]*[0-9]+[.)][ \t]+/, "", it)
        bullet_item(it, onum)
        next
    }

    # a line ending in two spaces is an explicit break, not a paragraph gap
    if (line ~ /  $/) {
        pending = (pending == "") ? trim(line) : pending " " trim(line)
        paragraph_tight(pending)
        pending = ""
        next
    }

    pending = (pending == "") ? trim(line) : pending " " trim(line)
}

END {
    if (pending != "") paragraph(pending)
    if (in_code) code_flush()
    if (TBLn > 0) table_flush()

    npages = page
    for (i = 1; i <= npages; i++) footer(i)

    doc = "%PDF-1.4\n"
    off[1] = length(doc) + 1
    doc = doc "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"

    kids = ""
    for (i = 1; i <= npages; i++) kids = kids " " (6 + (i - 1) * 2) " 0 R"
    off[2] = length(doc) + 1
    doc = doc "2 0 obj\n<< /Type /Pages /Kids [" kids " ] /Count " npages " >>\nendobj\n"

    off[3] = length(doc) + 1
    doc = doc "3 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>\nendobj\n"
    off[4] = length(doc) + 1
    doc = doc "4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>\nendobj\n"
    off[5] = length(doc) + 1
    doc = doc "5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>\nendobj\n"
    off[6] = length(doc) + 1
    doc = doc "6 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Oblique /Encoding /WinAnsiEncoding >>\nendobj\n"

    for (i = 1; i <= npages; i++) {
        po = 6 + (i - 1) * 2
        co = po + 1
        off[po] = length(doc) + 1
        doc = doc po " 0 obj\n<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R /F4 6 0 R >> >> /MediaBox [0 0 " pw " " ph "] /Contents " co " 0 R >>\nendobj\n"
        stream = C[i]
        off[co] = length(doc) + 1
        doc = doc co " 0 obj\n<< /Length " length(stream) " >>\nstream\n" stream "endstream\nendobj\n"
    }

    xstart = length(doc)
    highest = 6 + npages * 2
    xref = "xref\n0 " (highest + 1) "\n0000000000 65535 f \n"
    for (i = 1; i <= highest; i++) xref = xref sprintf("%010d 00000 n \n", off[i])
    trailer = "trailer\n<< /Size " (highest + 1) " /Root 1 0 R >>\nstartxref\n" xstart "\n%%EOF\n"

    printf "%s%s%s", doc, xref, trailer
    print npages > PAGESFILE
    close(PAGESFILE)
}
AWK

awk -v pw="$PW" -v ph="$PH" -v margin=54 \
    -v hdr="$HEADER" -v ftr="$FOOTER" \
    -v ttl="$TITLE" -v subtitle="$SUBTITLE" \
    -v PAGESFILE="$PAGES_FILE" \
    -f "$TMPD/md2pdf.awk" "$CLEAN_MD" > "$TMP_PDF" || {
    echo "$PROG: rendering failed" >&2
    exit 1
}

if [ ! -s "$TMP_PDF" ] || [ "$(head -c 5 "$TMP_PDF")" != "%PDF-" ]; then
    echo "$PROG: renderer produced no valid PDF" >&2
    exit 1
fi

mv -f "$TMP_PDF" "$OUT" || { echo "$PROG: cannot write $OUT" >&2; exit 1; }

PAGES=$(cat "$PAGES_FILE" 2>/dev/null || echo "?")
BYTES=$(wc -c < "$OUT" | tr -d ' ')

printf '[+] %s\n' "PDF written: $OUT"
printf '[+] %s\n' "Pages:       ${PAGES:-?}"
printf '[+] %s\n' "Size:        ${BYTES} bytes"
printf '[+] %s\n' "Source:      ${INPUTS[*]}"
exit 0
