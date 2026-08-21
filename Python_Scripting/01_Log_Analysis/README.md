# Activity 1: Log Analysis (Python)

This activity gives you five realistic, fictional incident logs to practice
log analysis and threat hunting with Python (`re`, `collections.Counter`,
plain file I/O). Each scenario is based on a common real-world attack
pattern, and each one exists because of a specific, well-known class of
security weakness. Understanding *why* the attack worked is as important
as spotting *that* it happened.

None of the companies, IPs, people, emails, or phone numbers in these logs
are real. They were generated for training purposes only.

## Folder layout

```
01_Log_Analysis/
  logs/       full incident logs, 2,500 lines each (about 1,000 malicious,
              about 1,500 ordinary/legitimate, interleaved chronologically)
  log_samples/ ~100-160 line excerpts pulled from the attack window of each log
  README.md   this file
```

## The five scenarios

Every log mixes a realistic volume of attack traffic with ordinary
day-to-day activity, the way a real production log would. Nothing is
isolated on its own; you have to filter the signal out of the noise.

### 1. `01_sql_injection_meridian_retail.log` — Meridian Retail Group

An online shop's `/product/detail?id=` parameter is hit with SQL injection
recon, sqlmap fingerprinting, a high-volume blind boolean-based extraction
campaign, and UNION-based dumps of five sensitive tables. The dumped
credentials are then used to bypass the login form outright and to take
over real customer accounts, followed by bulk exfiltration.

**The issue behind it**: user-supplied input was concatenated directly
into SQL queries instead of being passed through parameterized
queries/prepared statements, on *both* the product lookup and the login
form. Because the query text itself changed based on attacker input, a
single injection point cascaded into schema enumeration, credential
theft, and an authentication bypass. Parameterized queries (or an ORM
that enforces them), strict server-side input validation, and a
least-privilege database account would have stopped this at the first
payload.

### 2. `02_rce_vantage_cloud_systems.log` — Vantage Cloud Systems

A document portal is probed with JNDI/Log4Shell-style payloads, then
compromised via a malicious file upload disguised as an image. The
resulting webshell is used to fully take over two hosts (new privileged
user, cryptominer, cron persistence), sweep the internal network, and
beacon out to external infrastructure. A second, unrelated bot is also
seen hunting for other pre-existing webshells.

**The issue behind it**: untrusted input reached a code-execution sink
(a JNDI-lookup-style vulnerability), and separately, the file upload
feature trusted the client-supplied filename and extension instead of
validating the actual file content server-side, letting an executable
disguised with a double extension get stored and then run directly from
a public uploads path. Disabling dangerous lookup behavior, validating
uploads by content rather than name, and refusing to execute anything
from an uploads directory would each independently have prevented this.

### 3. `03_privilege_escalation_kestrel_manufacturing.log` — Kestrel Manufacturing Corp

A leaked internal API token dump is used to script a bulk attack against
a "change my own role" endpoint across hundreds of employee accounts.
Most tokens are stale, but a meaningful fraction succeed, and a subset of
those are used to create rogue admin accounts and commit payroll fraud,
including one detailed case of a warehouse employee inventing a duplicate,
fraudulent payroll identity for himself.

**The issue behind it**: broken access control. The endpoint let a user
set their *own* role field with no server-side authorization check
confirming that action was ever permitted for a non-admin account, and it
trusted a bearer token without confirming it was still valid for the
account presenting it. Every state-changing request needs server-side
authorization checks on the specific fields being changed, not just
"is this token valid at all," and sensitive fields like `role` should
never be client-writable through a general-purpose profile update.

### 4. `04_price_manipulation_bazario_marketplace.log` — Bazario Marketplace

A reseller/mule ring of dozens of fraudulent accounts checks out items
normally priced over $3,000 for $0.50 to $3.00 each, preceded by automated
probing of the cart's price validation logic.

**The issue behind it**: the checkout flow trusted a price value supplied
by the client instead of recalculating the authoritative price
server-side from the product catalog at the moment of payment. Any price,
discount, or total that appears in a request body should be treated as
untrusted input and recomputed from data the server controls; the client
should never be the source of truth for what something costs.

### 5. `05_bruteforce_solstice_health_networks.log` — Solstice Health Networks

Ordinary internet background scanning noise is mixed with two focused
credential-stuffing campaigns against real employee usernames on a
VPN/SSH jump host. One succeeds against a shared service account,
leading to lateral movement and exfiltration of a patient records
database, alongside routine legitimate admin SSH sessions.

**The issue behind it**: a shared service account with a weak, reused
password, reachable over SSH from the public internet, with no rate
limiting, account lockout, or multi-factor authentication to slow down
or stop repeated login attempts. Bans were eventually issued, but only
after the compromise. Key-based authentication instead of passwords,
MFA on anything internet-facing, and rate limiting from the start (not
just after damage is done) are the standard fixes here.

## What these five have in common

Map them against the OWASP Top 10 and the pattern is obvious: injection,
vulnerable/exploitable components, broken access control (twice), and
authentication failures are consistently among the most common root
causes of real breaches, year after year. None of these five incidents
required a novel technique. Every one of them exploited a well-documented,
well-understood class of mistake that a competent code review or a
standard security control would have caught.

## How to use this activity

1. Open the **sample** file for a scenario first (`log_samples/0X_..._sample.log`).
   It is a short, representative excerpt, not the full log, so it is easy to
   read end to end and small enough to paste into an AI prompt.
2. Study the sample and identify what "normal" traffic looks like versus
   what the attacker did, and see if you can spot the underlying issue
   described above just from the traffic pattern.
3. Prompt an AI assistant (or write it yourself) to generate a Python
   script that detects the pattern you found. A good starting prompt looks
   like this:

   > Here is a sample excerpt from a web server / auth log for a company
   > called [company name]. I believe it shows a [attack type] attack.
   > Paste the sample here. Write a Python script using the re module and
   > collections.Counter that parses this log format, flags the suspicious
   > activity, and prints a short incident summary (attacker IP, timeline,
   > and what was accessed or exfiltrated). Also have it generate a PDF
   > incident report.

4. Run the script you produce against the **full** log in `logs/` to see
   how it performs on the complete dataset, including all the background
   noise.

## A note on the data

The full logs mix realistic background traffic (ordinary customer,
employee, or admin activity) with the attack narrative, in the same way a
real production log would; roughly 60% of each log is unrelated, everyday
activity. Expect to filter out noise. The samples are shorter excerpts
centered on the attack window so they are easier to read and small enough
to hand to an AI assistant, but they still include some of that
surrounding noise on purpose.
