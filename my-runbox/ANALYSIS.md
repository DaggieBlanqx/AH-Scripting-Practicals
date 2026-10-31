# Case write-up — SQL injection on Meridian Retail

What this run box does, what the analyser found in
`../Bash_Scripting/01_Log_Analysis/logs/01_sql_injection_meridian_retail.log`,
and how those numbers were checked. For usage of the tool itself see
`README.md`.

## 1. Objective

Reconstruct a suspected SQL injection intrusion from a 2,500-line web access
log that mixes real attack traffic with ordinary customer activity, and
produce a report an analyst could hand to an incident lead: who attacked, from
where, in what order, what was touched, and what to do about it.

## 2. What is in the box

| File | Role |
|---|---|
| `utils/sqli_incident_analysis.sh` | The analyser: parser, detectors, aggregation, console output, Markdown report |
| `utils/sqli_incident_analysis.md` | Tool documentation: usage, options, coverage, output, limits |
| `reports/sqli_incident_<timestamp>.md` | The output for the last run |
| `README.md` | Index for the run box, linking every tool and document |
| `ANALYSIS.md` | This file: the case, the method, the validation |

## 3. How the analyser works

1. **Normalise.** Decompress `.gz`, strip CRLF, reject files that have no
   recognisable HTTP request lines (so a syslog or audit log cannot produce a
   verdict about a format that was never parsed).
2. **Classify in one pass.** Each line becomes one TSV row: client IP,
   timestamp (plus epoch seconds), method, path, status, bytes, user agent,
   tags, trailing `key=value` fields, and a percent-decoded copy of the
   request. Decoding matters: `OR 1=1` is transmitted as `OR%201=1` and would
   otherwise never match.
3. **Tag.** Payload families (boolean, time, error/metadata, UNION, stacked,
   blind inference), attack tooling user agents, post-exploitation markers,
   and behaviour (admin paths, login bursts, bulk transfers).
4. **Aggregate.** Per-stage counts with first/last seen and actor IPs, per-IP
   rollups, dump inventory, exfiltration volume, takeover accounting.
5. **Render.** Console narrative, then the Markdown report. The narrative is
   assembled from the findings, so an empty result reads as "nothing found"
   instead of describing someone else's breach.

## 4. What the log shows

The attack spans 14 Jul 03:00 to 15 Jul 09:18, in five distinguishable phases.

| Phase | Window | Evidence |
|---|---|---|
| Scanning | 14 Jul 03:00–03:16 | `AcunetixScanner` ×80 from 185.220.102.8, UNION/`SLEEP` probes on `/search` and `/product/detail` |
| Tooling takeover | 15 Jul 01:10–01:34 | `sqlmap/1.7.2` ×57 from 185.220.101.47 — column counting, schema enumeration, table dumps, destructive attempts that the WAF blocked |
| Blind extraction | 14 Jul 20:15–22:01 | 840 probes from 91.132.45.201 at 0.13 probes/s, 168 confirmed character matches |
| Bypass and theft | 15 Jul 01:25–01:32 | Login bypass, then 20 admin requests on the new session |
| Secondary fraud | 15 Jul 09:00–09:18 | 18 login attempts from 45.134.26.0/24, 6 takeovers, 6 fraudulent orders |

Detail worth reading out of the log:

* **Injection surface** — 980 requests against `/product/detail?id` (947) and
  `/search?q` (33). Two parameters, one root cause: string-concatenated SQL.
* **Payload mix** — boolean 22, time-based `SLEEP` 30, schema/metadata 13,
  UNION 83, stacked statements 2.
* **Blind campaign** — 840 probes, mean response 0.19 s, 168 confirmed
  character matches against `admin_accounts.password_hash` (640 probes) and
  `admin_accounts.api_key` (200). Every request returned 200 with a plausible
  size; the signal is the pattern, not an error page.
* **Dumps** — five tables (`users`, `saved_payment_methods`, `gift_cards`,
  `employee_payroll_view`, `admin_sessions`), eight paged requests each, 40
  pages of 50 rows, after `information_schema.tables`/`.columns` enumeration.
* **Bypass** — `username=admin'-- -&password=anything` from 185.220.101.47 at
  15 Jul 01:25:27: password comparison commented out, 302 to
  `/admin/dashboard`, session `sess_9f2c1a` issued.
* **Theft** — that session makes 20 requests from 185.220.101.52 (dashboard,
  customer list, eight exports, ten backup chunks), then 18 bulk transfers
  move **61.3 MB (64,307,891 bytes)**, largest 9.18 MB.
* **Fraud** — 12 rejected and 6 successful logins from three IPs in
  45.134.26.0/24 (a Python client, not a browser), then six
  `checkout/confirm` calls flagged `fraudulent_purchase`, one per taken-over
  account, each with its own phone number.
* **Detection gap** — the WAF blocked 2 stacked `DROP`/`UPDATE` statements
  (`rule=stacked_queries`) but not UNION dumps, blind inference or the login
  bypass. A single SOC alert fires at 01:38, after the data left.

Nothing in this case needed a novel technique: it is OWASP A03:2021
(injection) exploited on two surfaces, aggravated by a database account that
could read payroll, payment and session tables.

## 5. What the generated report contains

| Section | What it answers |
|---|---|
| Executive summary | What happened, in numbers, assembled from the findings |
| Attack timeline | Which stage, how many events, first/last seen, how many actors |
| Attack surface | Endpoints and parameters that carried payloads |
| Automated tooling | Which scanners/exploit frameworks, how many requests |
| Payload classes | Counts per injection family, with distinct sources |
| Blind extraction | Probe rate, confirmed matches, targeted columns |
| UNION dumps | Tables and the columns pulled from each |
| Authentication bypass | Payload, source, session, redirect |
| Post-bypass activity | Every request on the hijacked session |
| Data exfiltration | Size and path of each bulk transfer |
| Stuffing and takeover | Attempts/successes per IP, compromised accounts, fraudulent orders |
| Detection controls | WAF and SOC evidence, and what they missed |
| Indicators of compromise | IPs, session, tooling, dumped tables, exfil paths |
| Root cause and remediation | P0/P1/P2 actions tied to the actual failure |

Severity is derived, not written by hand: any bypass, exfiltration, takeover
or fraud ⇒ **CRITICAL**; injection confirmed without impact ⇒ **HIGH**;
tooling or probing only ⇒ **MEDIUM**; nothing ⇒ **NONE**.

## 6. How the numbers were verified

Every figure in the report was cross-checked against the raw log with
independent `grep`/`awk` one-liners before the script was trusted:

| Metric | Report | Independent check |
|---|---|---|
| Log lines / requests | 2500 / 2499 | `wc -l`; 1 SECURITY_ALERT line without an IP |
| Flagged rows | 1026 (41%) | rows carrying at least one tag |
| Attacker IPs | 7 | distinct tagged source addresses |
| SQLi requests | 980 | rows with a payload tag |
| UNION / SLEEP / boolean / schema / stacked | 83 / 30 / 22 / 13 / 2 | `grep -c` on the decoded log |
| Blind probes / matches | 840 / 168 | `blind_probe` / `MATCH_CONFIRMED` counts |
| Targeted columns | password_hash 640, api_key 200 | `SUBSTRING((SELECT …` occurrences |
| Tables dumped | 5 × 8 requests, 40 pages of 50 | `FROM <table>` and `LIMIT a,b` counts |
| Bypass / session requests | 1 / 20 | `AUTH_BYPASS_SUCCESS`, `cookie=sess_9f2c1a` |
| Exfiltration | 18 requests, 64,307,891 bytes | `EXFIL_CANDIDATE` count and byte sum |
| Takeovers / rejections / orders | 6 / 12 / 6 | the three success/failure/order markers |
| WAF blocks / SOC alerts | 2 / 1 | marker counts |

Behavioural checks were also run:

* **Sample log** (attack window excerpt) → exit 2, same stages, smaller counts.
* **Synthetic clean log** → exit 0, verdict NONE, and a "nothing found"
  narrative (not a copied breach story).
* **gzip input** and **CRLF input** → identical results to the plain log.
* **Empty file** → exit 0, no crash, no division by zero.
* **Other course logs**: the RCE access log analyses cleanly (MEDIUM, no SQLi);
  the audit log, the order log and the SSH syslog are rejected with exit 1
  and an explicit "not an HTTP access log" message rather than a bogus verdict.
* **CLI contract**: `--help` 0, missing file 1, unknown option 1, two operands
  1, `--` handled positionally.

## 7. Decisions and constraints

* **Markdown only.** The report is plain Markdown — no rendering toolchain,
  no external report dependencies.
* **Repo-rooted paths.** Reports show `/africahackon-course/...` instead of an
  absolute home path, so they can be shared without leaking a workstation
  layout.
* **Data-driven narrative.** Severity, summary paragraphs and remediation are
  computed from the findings, which is what makes the tool reusable on the
  other logs without producing nonsense on a clean one.
* **Single log, single pass.** The analyser reads one file and writes one
  report; it needs no index, database or state between runs.
* **Portable awk.** Written for `mawk` as well as `gawk`: no interval
  expressions, no `gensub`, no `bc`.

## 8. Limits and next steps

* Marker-based stages depend on the log being enriched by the application or
  WAF. Without them the payload and behaviour detectors still work, but
  "confirmed" events (bypass, takeover, exfiltration) cannot be labelled as
  confirmed.
* Blind-injection detection is heuristic (`ASCII(SUBSTRING`, probe markers,
  burst behaviour). A legitimate feature that sends similar SQL-shaped
  parameters would need a volume threshold before alerting.
* No cross-log correlation: correlating this access log with the auth log or
  the firewall log would tighten the ATO and exfiltration picture.
* No reputation or geo enrichment of source addresses, and no PCAP-level
  analysis — that belongs to the threat-hunting activity, not this one.
