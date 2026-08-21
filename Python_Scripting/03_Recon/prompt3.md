# RECON TASKING: OPERATION PAPER TRAIL

```
FROM:     Engagement Lead
TO:       Recon Operator (you)
SUBJECT:  Leaked credential discovery across a GitHub org or repo
TOOLING:  GitPython/git, GitHub REST API (requests), Python
PRIORITY: The mistake someone committed and forgot about
```

Ports and subdomains are the front door. This one's about the mistake
that's already sitting in plain sight: a developer who hardcoded an AWS
key to test something quickly, committed it, deleted it in the next
commit, and never once removed it from history. Git doesn't forget.

GitHub is one of the highest-value recon targets there is precisely
because organizations treat their commit history as private when it's
often fully public, and because secrets that were "removed" in a later
commit are still sitting there for anyone willing to look.

## Your mission

Build a Python toolkit that takes a single GitHub URL, either an
**organization** (`https://github.com/someorg`) or a **specific
repository** (`https://github.com/someorg/somerepo`), and scans it for
leaked credentials and secrets, **including in commit history, not just
the current files**.

## The one rule that matters most

**Forked repositories must be excluded.** A fork shows up under the
org's account but the code (and its history) belongs to whoever wrote
it upstream. Scanning forks pollutes your findings with secrets that
have nothing to do with your actual target, wastes your scan budget, and
can misattribute a finding to the wrong organization entirely. Get this
filter right before anything else works.

## Before you prompt the AI

Know the two GitHub API facts you'll lean on:
- `GET /orgs/{org}/repos` lists an org's repositories, and each repo
  object in the JSON response has a `"fork"` boolean key, exactly what
  you need to exclude forks.
- Unauthenticated GitHub API requests are rate-limited hard (60/hour).
  A `GITHUB_TOKEN` personal access token, sent as a Bearer token, bumps
  that to 5,000/hour, and you'll want it for anything beyond a tiny org.

## The prompt

```
I'm building a Python-based reconnaissance toolkit for authorized
security engagements. I need a script that takes a single GitHub URL,
either an organization (https://github.com/someorg) or a specific
repository (https://github.com/someorg/somerepo), and scans it for
leaked credentials and secrets, including in git commit history, not
just the current file tree. This is for organizations/repositories I am
explicitly authorized to assess (either my own, or in scope for a
security engagement or an authorized bug bounty program). Auto-install
any missing dependencies (requests, and GitPython if you use it) with
pip the first time the script runs, so I don't have to set anything up
by hand.

Requirements:

1. Parse the input URL (urllib.parse) and detect whether it points at an
   organization or a specific repository, and behave accordingly.

2. If given an organization:
   - Use the GitHub REST API (via the requests library) to list all of
     its repositories, handling pagination properly (follow the Link
     header, or increment the page param until an empty page comes
     back).
   - THIS IS CRITICAL: filter out any repository dict where
     repo["fork"] is True. Only scan repos the organization actually
     owns the code for. Print a clear count of "N repos found, M
     excluded as forks, scanning the remaining K" so I can see the
     filter working.
   - Support a GITHUB_TOKEN environment variable (os.environ.get), used
     as a Bearer token in the Authorization header if present, to raise
     the rate limit from 60/hour to 5,000/hour. If it's not set, warn me
     that I'm rate-limited and may need to slow down or provide a token
     for anything beyond a handful of repos.
   - Respect rate limiting: check the X-RateLimit-Remaining response
     header on every call and sleep until X-RateLimit-Reset (or stop
     with a clear resume-later message) before hitting the limit, rather
     than failing ungracefully mid-scan with a 403.

3. For each repository to be scanned:
   - Clone it to a temporary working directory (tempfile.mkdtemp()) with
     full history (not a shallow/depth=1 clone, since the whole point is
     scanning history for things that were later deleted). You can shell
     out to git via subprocess, or use GitPython, your call, but justify
     it in a comment.
   - Search the full commit history, not just the current checkout, for
     secret patterns. At minimum, detect (as compiled `re` patterns):
     - AWS access keys (AKIA[0-9A-Z]{16} and similar patterns for secret
       keys)
     - Private key headers (-----BEGIN RSA PRIVATE KEY-----, -----BEGIN
       OPENSSH PRIVATE KEY-----, -----BEGIN PGP PRIVATE KEY BLOCK-----,
       etc.)
     - Slack tokens (xox[baprs]-...)
     - Generic API-key-shaped assignments (api_key=, apikey:, secret=,
       token= followed by a long alphanumeric string)
     - .env-style files that were ever committed (filename match across
       history is enough here, don't just rely on content patterns)
     - Database connection strings with embedded credentials
       (postgres://user:pass@..., mongodb://user:pass@..., etc.)
     Use `git log -p` (via subprocess, capturing stdout) run against
     every commit, or `git grep` across all revisions, whichever you can
     implement most robustly and efficiently in Python.
   - For every match, record: repository name, file path, commit hash
     (short form), commit date, matched pattern type, and a REDACTED
     version of the match (show only the first 4 and last 4 characters
     of the actual matched secret, mask the rest with asterisks). Do
     not print full secret values into the report, since the report
     itself might get shared more widely than the raw finding should be.
   - Delete the temporary clone after scanning it, whether the scan
     succeeded or failed, using a try/finally with shutil.rmtree, so I'm
     not left with dozens of cloned repos eating disk space.

4. Produce a final report (print to console, and also write a JSON file)
   grouped by repository, sorted so the repository with the most
   findings appears first. Include a one-line executive summary at the
   top: total repos scanned, total forks excluded, total findings, and
   a breakdown of findings by pattern type (collections.Counter is
   perfect for this).

5. Handle these failure cases gracefully with clear messages, not raw
   tracebacks:
   - the GitHub URL doesn't match either expected format
   - the organization or repository doesn't exist or is private/
     inaccessible (a 404 from the API)
   - git is not installed (catch FileNotFoundError from subprocess)
   - a clone fails partway through (skip that repo, log it, keep going
     with the rest rather than aborting the whole run)
   - GITHUB_TOKEN is invalid or expired (a 401 from the API)

6. Add a prominent module-level docstring covering:
   - This must only be run against organizations/repositories you own or
     are explicitly authorized to assess, and scanning third-party
     public repos without authorization, even though the code is
     public, may exceed the scope of what's ethical or permitted under
     a given program's rules.
   - If a real secret is found during an authorized engagement, it
     should be reported through the engagement's proper disclosure
     channel immediately, not left sitting in a plaintext report file,
     and the repository owner should be encouraged to rotate the
     credential regardless of whether it looks "old."

Structure the code with clear separation between the GitHub API layer
(listing + fork-filtering), the git layer (clone + history scanning),
and the reporting layer, so I could swap in a dedicated tool later
(trufflehog or gitleaks) as the actual scanning engine behind the same
org-enumeration-and-fork-filtering front end, since that front end is
the part most worth reusing.
```

## After you get a script

Test it against a throwaway GitHub org you control, with at least one
repo that has a forked copy and one that doesn't, and confirm the fork
gets excluded and logged as excluded, not silently dropped. Then commit
a fake, obviously-non-functional secret (e.g. `AKIAABCDEFGHIJKLMNOP` is
a syntactically valid but non-real-looking AWS key format) to a test
file, delete it in the next commit, push, and confirm your script still
finds it in history. That's the whole point of scanning history instead
of just the current tree, prove it actually does that.
