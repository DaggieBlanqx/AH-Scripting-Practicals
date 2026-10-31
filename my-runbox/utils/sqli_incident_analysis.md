# sqli_incident_analysis.sh

Analyses a web access log for SQL injection activity and writes a Markdown
incident report: scanning, payload probing, blind extraction, data dumps,
login bypass, post-exploitation and follow-on fraud.

Tool: [`sqli_incident_analysis.sh`](sqli_incident_analysis.sh) ·
Index: [`../README.md`](../README.md) · Case write-up: [`../ANALYSIS.md`](../ANALYSIS.md)

## Usage

```bash
./sqli_incident_analysis.sh [options] [LOGFILE]
```

| Option | Meaning |
|---|---|
| `LOGFILE` | Access log to analyse. `.gz` is decompressed on the fly. Defaults to the activity's sample log (`01_sql_injection_meridian_retail.log`), looked up in this folder, `./logs/`, `../logs/`, `../log_samples/` and the activity folders, so the tool runs from wherever it was copied to. |
| `-o, --out DIR` | Report directory. Default: `./reports` when it exists next to the tool, otherwise `../reports`. |
| `-q, --quiet` | Skip the console output; the report file is still written. |
| `-h, --help` | Usage summary. |

Examples:

```bash
./sqli_incident_analysis.sh                                  # default log
./sqli_incident_analysis.sh /var/log/nginx/access.log.gz     # any access log
./sqli_incident_analysis.sh -q -o /tmp/triage                 # batch/cron use
```

Exit status:

| Code | Meaning |
|---|---|
| `0` | Log parsed; no attack indicators found |
| `2` | Log parsed; attack indicators found |
| `1` | Usage error, unreadable input, or a file that is not an HTTP access log |

## Input format

The Apache/Nginx "combined" format, optionally followed by the `key=value`
fields an application or WAF appends to a line:

```
IP - - [DD/Mon/YYYY:HH:MM:SS +0000] "METHOD /path HTTP/1.1" STATUS BYTES \
     "REFERER" "USER-AGENT"  key=value ... [marker]
```

Requests are percent-decoded before matching, so `OR%201=1` is still seen as
`OR 1=1`. Optional markers understood when present: `blind_probe`,
`AUTH_BYPASS_SUCCESS`, `ACCOUNT_TAKEOVER_SUCCESS`, `EXFIL_CANDIDATE`,
`WAF_BLOCK`, `SECURITY_ALERT`, `fraudulent_purchase`. Lines without markers
are classified from the payload and behaviour alone.

Anything that is not an HTTP access log (syslog, application audit logs, CSV)
is rejected with a clear message instead of being forced through the parser.

## What it detects

* **Tooling** — `sqlmap`, `Acunetix`, `nikto`, `nuclei`, `dirbuster`,
  `gobuster`, `ffuf`, `wpscan`, `masscan`, `nmap`, `hydra`, ...
* **Payload families** — boolean (`OR 1=1`, `OR '1'='1'`), time-based
  (`SLEEP(`, `BENCHMARK(`, `PG_SLEEP`), error/metadata (`information_schema`,
  `extractvalue`, `updatexml`, `@@version`, `load_file`, `CONVERT(int`),
  UNION, stacked/destructive (`DROP TABLE`, `UPDATE … SET`), blind inference
  (`ASCII(SUBSTRING((SELECT …))`, probe markers).
* **Post-exploitation** — authentication bypass, session reuse, admin-area
  requests, bulk export/backup transfers.
* **Account abuse** — login bursts, rejected logins, successful takeovers,
  fraudulent order confirmations.
* **Controls** — WAF blocks and SOC alerts recorded inline in the log.

## Output

One Markdown file per run: `reports/sqli_incident_<UTC timestamp>.md`.

It contains the executive summary (data-driven — a clean log gets a "nothing
found" report, not a borrowed breach narrative), the stage timeline, attack
surface, payload classes, blind-extraction campaign, UNION dumps, login
bypass, post-bypass activity, exfiltration inventory, credential stuffing and
account takeover, detection-control gaps, indicators of compromise and
prioritised remediation.

Severity is derived from the findings: bypass, exfiltration, takeover or
fraud ⇒ CRITICAL; injection confirmed without impact ⇒ HIGH; tooling or
probing only ⇒ MEDIUM; nothing ⇒ NONE. Paths inside the report are rooted at
the repository (`/africahackon-course/...`) rather than at a home directory,
so reports can be shared as-is.

## Using it on another log

The detectors are signature- and behaviour-based, not case-specific: point the
tool at another access log and it reports whatever stages are present,
silencing the rest. Two things are worth knowing before trusting a result:

* Marker-based tags (`AUTH_BYPASS_SUCCESS` and friends) only fire when the
  application/WAF that produced the log actually writes them. Everything else
  is detected from the payload and response pattern, so a plain log still
  works — it just reports a little less.
* A log that mixes request lines with other content still parses, but the
  counts are only as good as the input. Check the "Log lines" summary line
  (parsed / meta / unparsable) at the start of a run.

## Extending it

Detection rules live in one place — the classifier block, where each tag is
assigned from the decoded request plus the trailing fields. Adding a payload
family means adding one rule there and a label for it; the console and report
sections pick new tags up through the stage list.

## Known limits

* Confirmed-event language (bypass, takeover, exfiltration) depends on the log
  carrying the corresponding markers; without them the tool reports the same
  behaviour as unconfirmed indicators.
* Blind-injection detection is heuristic (`ASCII(SUBSTRING`, probe markers,
  burst behaviour), so a legitimate feature that sends similar SQL-shaped
  parameters would need a volume threshold before alerting.
* One log per run: no correlation with auth, firewall or application logs, and
  no reputation or geo enrichment of source addresses.
