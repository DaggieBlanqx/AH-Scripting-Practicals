# RECON TASKING: OPERATION FIRST LIGHT

```
FROM:     Engagement Lead
TO:       Recon Operator (you)
SUBJECT:  Attack surface discovery + continuous monitoring
TOOLING:  subfinder, Bash
PRIORITY: Foundation for everything that follows
```

Every engagement starts the same way: you don't know what you don't know.
Before anyone can scan a port, fuzz a parameter, or write a single
exploit, someone has to answer the most basic question there is: **what
does this organization actually have on the internet?**

Subdomains are where attack surface hides. Forgotten staging environments,
old marketing microsites, an internal admin panel someone exposed "just
for testing," a dev API that never got taken down, they all live on
subdomains nobody's looking at. Your job is to find them, then keep
watching, because new ones appear the moment you stop.

## Your mission

Build a Bash toolkit around [`subfinder`](https://github.com/projectdiscovery/subfinder)
that does two things:

1. **Enumeration** - given one or more root domains, find every subdomain
   you can, cleanly and repeatably.
2. **Monitoring** - run enumeration again later, diff it against last
   time, and loudly tell the operator when something new shows up. New
   subdomains mid-engagement are either fresh attack surface or a sign
   the target just deployed something worth looking at immediately.

## Before you prompt the AI

Have a rough idea of what "done" looks like so you can judge what comes
back:

- One script (or a small pair) that can enumerate on demand and also run
  in a repeating "watch" mode.
- Results saved per-domain, per-run, with a timestamp, so you can always
  answer "when did we first see this subdomain?"
- A diff step that's obvious to read: new entries clearly marked, nothing
  buried in noise.
- It should not explode if `subfinder` isn't installed, if the network
  hiccups, or if a domain has zero results.

## The prompt

```
I'm building a Bash-based reconnaissance toolkit for authorized security
engagements. I need a script (or small set of scripts) built around the
subfinder CLI tool that does subdomain enumeration AND ongoing subdomain
monitoring. This is for domains I am explicitly authorized to test, as
part of a scoped engagement.

Requirements:

1. Accept one or more root domains as input, either as command-line
   arguments or as a file with one domain per line (-l/--list style flag).

2. For each domain, run subfinder with sensible defaults (recursive
   sources, silent output) and save the results to a per-domain file
   under a results directory, structured like:
   results/<domain>/<domain>_YYYYMMDD_HHMMSS.txt

   Also maintain results/<domain>/latest.txt as a symlink or copy of the
   most recent run, so later steps always have an easy "current state"
   to read.

3. Add a "monitor" mode that:
   - Runs subfinder again for a given domain (or all domains previously
     enumerated).
   - Diffs the new result against the previous latest.txt using comm/diff.
   - Prints a clearly labeled "NEW SUBDOMAINS FOUND" section if anything
     appeared that wasn't there last time, and a "REMOVED" section if
     anything disappeared (useful signal too, e.g. decommissioned
     services).
   - If nothing changed, say so explicitly rather than printing nothing
     (I want to know the check ran, not just that it found nothing).
   - Appends any new subdomains found to a running
     results/<domain>/new_subdomains_log.txt with timestamps, so I have
     a full history of when each subdomain first appeared, not just the
     latest diff.

4. Make monitor mode usable both as a one-shot check (I call it manually
   or from cron) and as a long-running loop with a configurable interval
   (e.g. --interval 3600 to check hourly), whichever is simpler and more
   robust to implement well.

5. Handle these failure cases gracefully with clear error messages, not
   silent failures or a wall of stack traces:
   - subfinder is not installed or not on PATH (tell me exactly how to
     install it: "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
   - a domain returns zero subdomains
   - the results directory doesn't exist yet on first run
   - subfinder exits with a non-zero status

6. Normalize output before diffing/storing: lowercase everything, strip
   any trailing dots, sort and deduplicate, so the diff step doesn't
   produce false positives from formatting differences between runs.

7. Print a short summary at the end of every run: how many subdomains
   total, how many new since last run, how long the enumeration took.

8. Add a top-of-file comment block reminding whoever runs this that it
   must only be pointed at domains they are explicitly authorized to
   test, since subdomain enumeration is reconnaissance against someone
   else's infrastructure even when it uses only public data sources.

Write it as clean, well-commented Bash using functions, not one giant
linear script, so I can extend it later (e.g. wiring the "new
subdomains found" event to a Slack or Discord webhook).
```

## After you get a script

Run enumeration against a domain you control or are authorized to test.
Then run monitor mode again a little later, ideally after something on
that domain has actually changed (spin up a throwaway subdomain if you
need to prove the diff logic works). You should see it flagged clearly.

If you want to push further: wire the "new subdomain found" event to a
notification (webhook, email, whatever you have available), so this
becomes something you'd actually leave running during a real engagement
instead of a one-off script you run once and forget.
