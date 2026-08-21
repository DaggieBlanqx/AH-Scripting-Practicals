# RECON TASKING: OPERATION PAPER TRAIL

```
FROM:     Engagement Lead
TO:       Recon Operator (you)
SUBJECT:  Leaked credential discovery across a GitHub org or repo
TOOLING:  git, GitHub API (curl), Bash
PRIORITY: The mistake someone committed and forgot about
```

Ports and subdomains are the front door. This one's about the mistake
that's already sitting in plain sight: a developer who hardcoded an AWS
key to test something quickly, committed it, deleted it in the next
commit, and never once removed it from history. `git log` doesn't forget.

GitHub is one of the highest-value recon targets there is precisely
because organizations treat their commit history as private when it's
often fully public, and because secrets that were "removed" in a later
commit are still sitting there for anyone willing to look.

## Your mission

Build a Bash toolkit that takes a single GitHub URL, either an
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
  object has a `fork` boolean field, exactly what you need to exclude
  forks.
- Unauthenticated GitHub API requests are rate-limited hard (60/hour).
  A `GITHUB_TOKEN` personal access token bumps that to 5,000/hour, and
  you'll want it for anything beyond a tiny org.

## The prompt

```
I'm building a Bash-based reconnaissance toolkit for authorized security
engagements. I need a script that takes a single GitHub URL, either an
organization (https://github.com/someorg) or a specific repository
(https://github.com/someorg/somerepo), and scans it for leaked
credentials and secrets, including in git commit history, not just the
current file tree. This is for organizations/repositories I am
explicitly authorized to assess (either my own, or in scope for a
security engagement or an authorized bug bounty program).

Requirements:

1. Parse the input URL and detect whether it points at an organization
   or a specific repository, and behave accordingly.

2. If given an organization:
   - Use the GitHub REST API (via curl) to list all of its repositories,
     handling pagination properly (the API paginates at 30-100 per page
     depending on params; follow the Link header or use the per_page/page
     params until an empty page comes back).
   - THIS IS CRITICAL: filter out any repository where the API's "fork"
     field is true. Only scan repos the organization actually owns the
     code for. Print a clear count of "N repos found, M excluded as
     forks, scanning the remaining K" so I can see the filter working.
   - Support a GITHUB_TOKEN environment variable, used as a Bearer token
     in the Authorization header if present, to raise the rate limit
     from 60/hour to 5,000/hour. If it's not set, warn me that I'm
     rate-limited and may need to slow down or provide a token for
     anything beyond a handful of repos.
   - Respect rate limiting: check the X-RateLimit-Remaining response
     header and pause (or stop with a clear resume-later message) before
     hitting the limit, rather than failing ungracefully mid-scan.

3. For each repository to be scanned:
   - Clone it to a temporary working directory (use mktemp -d) with full
     history (not --depth 1, since the whole point is scanning history
     for things that were later deleted).
   - Search the full commit history, not just the current checkout, for
     secret patterns. At minimum, detect:
     - AWS access keys (AKIA[0-9A-Z]{16} and similar patterns for secret
       keys)
     - Private key headers (-----BEGIN RSA PRIVATE KEY-----, -----BEGIN
       OPENSSH PRIVATE KEY-----, -----BEGIN PGP PRIVATE KEY BLOCK-----,
       etc.)
     - Slack tokens (xox[baprs]-...)
     - Generic API-key-shaped assignments (api_key=, apikey:, secret=,
       token= followed by a long alphanumeric string)
     - .env-style files that were ever committed (filename match is
       enough here, don't just rely on content patterns)
     - Database connection strings with embedded credentials
       (postgres://user:pass@..., mongodb://user:pass@..., etc.)
     Use `git log -p` piped through grep -E with these patterns, or
     `git grep` across all revisions if that's more reliable, whichever
     you can implement most robustly in Bash.
   - For every match, record: repository name, file path, commit hash
     (short form), commit date, matched pattern type, and a REDACTED
     version of the match (show only the first 4 and last 4 characters
     of the actual matched secret, mask the rest with asterisks). Do
     not print full secret values into the report, since the report
     itself might get shared more widely than the raw finding should be.
   - Delete the temporary clone after scanning it, whether the scan
     succeeded or failed, so I'm not left with dozens of cloned repos
     eating disk space (use a trap to guarantee cleanup even on error
     or interrupt).

4. Produce a final report, grouped by repository, sorted so the
   repository with the most findings appears first. Include a one-line
   executive summary at the top: total repos scanned, total forks
   excluded, total findings, and a breakdown of findings by pattern
   type.

5. Handle these failure cases gracefully with clear messages:
   - the GitHub URL doesn't match either expected format
   - the organization or repository doesn't exist or is private/inaccessible
   - git or curl is not installed
   - a clone fails partway through (skip that repo, log it, keep going
     with the rest rather than aborting the whole run)
   - GITHUB_TOKEN is invalid or expired (a 401 from the API)

6. Add a prominent comment block at the top of the script covering:
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

Write it as clean, well-commented Bash using functions, structured so I
could swap in a dedicated tool later (trufflehog or gitleaks) as the
actual scanning engine behind the same org-enumeration-and-fork-filtering
front end, since that front end is the part most worth reusing.
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
