# md2pdf.sh

Converts Markdown into a paginated PDF. Re-usable on any Markdown file: point
it at a document and get a printable report back, with no pandoc, LaTeX,
Python or Ghostscript in the loop — just bash, POSIX awk and coreutils.

Tool: [`md2pdf.sh`](md2pdf.sh) · Index: [`../README.md`](../README.md)

## Usage

```bash
./md2pdf.sh [options] FILE.md [FILE2.md ...]
```

| Option | Meaning |
|---|---|
| `FILE.md` | Input document. `-` reads standard input. Several files are concatenated in order, so a set of reports can be bound into one PDF. |
| `-o, --out FILE` | Output PDF. Default: the first input with a `.pdf` suffix, in the same directory. |
| `-t, --title TEXT` | Title printed in the header of continuation pages. Default: the document's first H1. |
| `--subtitle TEXT` | Subtitle printed under the first-page heading rule. |
| `-s, --size SIZE` | `a4` (default) or `letter`. |
| `--no-header` | Do not print the title on continuation pages. |
| `--no-footer` | Do not print page numbers. |
| `-h, --help` | Usage summary. |

Examples:

```bash
./md2pdf.sh report.md                        # -> report.pdf beside it
./md2pdf.sh report.md -o out/incident.pdf    # explicit destination
./md2pdf.sh notes.md annex.md -o bundle.pdf  # two documents, one PDF
./md2pdf.sh - -o piped.pdf < report.md       # from standard input
./md2pdf.sh report.md -t "Incident report" --subtitle "Meridian Retail"
```

Exit status:

| Code | Meaning |
|---|---|
| `0` | PDF written |
| `1` | Usage error, unreadable input, or input with no content |

## Markdown supported

| Construct | Rendering |
|---|---|
| `#` … `######` headings | Bold, size and colour scale with the level; H1 gets a rule and optional subtitle |
| Paragraphs | Wrapped to the measure; consecutive lines join |
| Line ending in two spaces | Explicit line break, one line per field |
| `**bold**`, `*italic*`, `` `code` `` | Real bold / oblique / monospace runs, mid-word safe |
| `[text](url)`, `![alt](src)` | Rendered as their visible text; URLs are not printed |
| `-`/`*`/`+` and `1.`/`2)` lists | Hanging indent, square bullet or number |
| `>` block quotes | Indented, grey, with a left bar |
| Fenced code blocks (`​``` `) | Monospace in a tinted panel with a left rule; long lines fold at the measure |
| `\|` tables | Header row shaded, columns sized to content then scaled to fit, header repeated after a page break |
| `---`, `***`, `___` | Horizontal rule |
| HTML comments and tags | Dropped |
| YAML front matter | Skipped (only when the line after `---` is `key:`) |

## Output format

Classic PDF 1.4 with one uncompressed content stream per page, A4 or Letter,
54 pt margins, Helvetica body text (bold, oblique and Courier variants for
emphasis and code), navy headings, a footer with the page number and, on
continuation pages, the document title in the header. Because nothing is
compressed, the PDF is readable with `strings` and diff-friendly.

Text is transliterated to ASCII first (em dash, curly quotes, ellipsis,
arrows, bullets) since the built-in font encodings only carry printable
ASCII; anything else is dropped rather than printed as mojibake.

## How it works

1. Inputs are concatenated, then transliterated by `sed`.
2. One awk pass parses the Markdown, lays out each block (measuring lines with
   average glyph widths), and writes the PDF syntax — objects, content
   streams, xref offsets — to standard output.
3. Bash validates the result starts with `%PDF-`, moves it into place and
   reports the page count and size.

Each drawn line is a single PDF text object whose style switches happen
inside it, so the viewer's own glyph advances keep mixed bold/italic/code runs
from overlapping even though the wrap width is an estimate.

## Known limits

* No images are embedded — `![alt](src)` becomes its alt text.
* Lists do not nest; a nested list renders at the same indent as its parent.
* Emphasis does not nest (`**bold with *italic* inside**` keeps the outer
  style), and `_underscore_` emphasis is not interpreted, so `snake_case`
  words stay intact.
* Table cells are single-line: an over-long cell is cut with `..` rather than
  wrapped, and very wide tables are squeezed to the page width.
* Only the built-in Helvetica/Courier fonts are used, so non-Latin scripts
  (CJK, Cyrillic, Arabic) are transliterated away rather than rendered.
