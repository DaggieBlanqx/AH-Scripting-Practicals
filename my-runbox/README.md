# Run box

Workspace for the hand-written Bash tooling built during the scripting
practicals: one folder holding the reusable tools (in `utils/`), their
documentation, and the reports they produce. This file is the index — start
here, then follow the link to whichever tool or document you need.

No Python, no `bc`, no `gawk`, no external renderers, no network: everything
here runs on bash, POSIX awk and coreutils.

## Contents

| Path | Type | Purpose |
|---|---|---|
| [`utils/sqli_incident_analysis.sh`](utils/sqli_incident_analysis.sh) | tool | Web access log analyser: reconstructs a SQL injection intrusion and writes a Markdown incident report |
| [`utils/sqli_incident_analysis.md`](utils/sqli_incident_analysis.md) | doc | Usage, options, detection coverage and output for that tool |
| [`utils/md2pdf.sh`](utils/md2pdf.sh) | tool | Markdown to PDF converter: renders any Markdown document into a paginated, printable PDF |
| [`utils/md2pdf.md`](utils/md2pdf.md) | doc | Usage, supported Markdown, output format and limits for the converter |
| [`ANALYSIS.md`](ANALYSIS.md) | doc | Case write-up: what the analyser found, how the numbers were verified, decisions and limits |
| [`package.json`](package.json) | runner | npm scripts that call the tools with common argument sets (`npm run analyse`, `npm run report`, ...) |
| [`reports/`](reports/) | output | Generated reports, one file per run, named `<tool>_<UTC timestamp>.md` |

## Quick start

```bash
cd my-runbox

npm run analyse                    # analyse the default activity log
npm run report                     # analyse, then convert the newest report to PDF
npm run pdf -- reports/REPORT.md   # convert a specific Markdown file
npm run help                       # usage for both tools

# the same thing without npm:
./utils/sqli_incident_analysis.sh
./utils/md2pdf.sh reports/REPORT.md
```

| Script | What it runs |
|---|---|
| `npm run analyse` / `analyse:quiet` | The analyser; quiet suppresses the console summary |
| `npm run report` | Analyser, then converts the newest report in `reports/` to PDF |
| `npm run pdf -- FILE.md` | The converter on one file |
| `npm run pdf:latest` / `pdf:all` | Convert the newest report, or every Markdown file in `reports/` |
| `npm run help` / `docs` | Tool usage, or the contents of this README |
| `npm run lint` | `bash -n` syntax check on both tools |
| `npm run smoke` | End-to-end self-test: analyse, convert, check the PDF header |

No install step is needed — there are no dependencies; npm only runs the
scripts. Exit codes pass through (`2` still means "attack indicators found").

Analyser reports land in `reports/` at the top of the run box and the console
prints the path. The converter writes its PDF beside the Markdown it was given unless
`-o` says otherwise.

## Tools

| Tool | What it does | Docs | Status |
|---|---|---|---|
| `sqli_incident_analysis.sh` | Classifies every request in an Apache/Nginx access log, tags SQL injection payload families, tooling and post-exploitation markers, and reports each stage with counts, timeline, actors and IOCs | [`utils/sqli_incident_analysis.md`](utils/sqli_incident_analysis.md) | ready |
| `md2pdf.sh` | Renders Markdown to a paginated PDF — headings, lists, code blocks, tables, quotes — with no external converters or renderers | [`utils/md2pdf.md`](utils/md2pdf.md) | ready |

## Documents

| Document | Read it when |
|---|---|
| `README.md` (this file) | you want to know what is in the box and where to start |
| `utils/sqli_incident_analysis.md` | you are running or extending the log analyser |
| `utils/md2pdf.md` | you are converting Markdown to PDF or want to know what is supported |
| `ANALYSIS.md` | you want the case narrative, the validation trail and the known limits |

## Conventions

Conventions exist so the folder keeps working as the tool count grows.

**Naming.** A tool lives in `utils/`: `utils/<tool>.sh`, executable, with a
matching `utils/<tool>.md` document next to it. Helper libraries that are not run directly get no `.md`
and are mentioned in their consumers' docs. Reports keep the tool's name:
`reports/<tool>_<UTC timestamp>.md`.

**Self-containment.** Each tool runs from this folder with no arguments,
resolving its inputs and outputs relative to itself, and never depending on
the caller's working directory. Analysers write into `reports/`; converters
write beside the file they were given unless `-o` says otherwise. Dependencies
are bash, POSIX awk and coreutils only.

**Interfaces.** Console summary plus a file artifact by default; `-q` silences
the console, `-o DIR` moves the output, `-h` prints usage. Exit status is
meaningful for automation: `0` clean, `2` findings, `1` usage or input error.
Human-facing paths are rooted at the repository (`/africahackon-course/...`),
never at a home directory, so reports can be shared as-is.

**Docs discipline.** Usage detail belongs in the tool's own `.md`; this README
stays a thin index that lists every tool and links to it. When a tool is added
or retired, its row in **Contents** and **Tools** changes in the same edit.

## Adding a tool

1. Drop `utils/<tool>.sh`, `chmod +x`, same CLI shape as the others.
2. Write `utils/<tool>.md`: purpose, usage, options, input format, what it
   detects or does, output, exit codes, known limits.
3. Add two rows to this README — one under **Contents**, one under **Tools** —
   and link the new doc.
4. Confirm it runs from this folder with no arguments and writes only inside
   `reports/`.
