# RECON TASKING: OPERATION FIRST LIGHT

```
FROM:     Engagement Lead
TO:       Recon Operator (you)
SUBJECT:  Attack surface discovery + continuous monitoring
TOOLING:  subfinder, Python
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

Build a Python toolkit around [`subfinder`](https://github.com/projectdiscovery/subfinder)
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

- `subfinder` itself is a Go binary; your Python script's job is to
  invoke it (via `subprocess`), capture and parse its output, persist
  state between runs, and do the diffing, notification, and reporting
  around it.
- Results saved per-domain, per-run, with a timestamp, so you can always
  answer "when did we first see this subdomain?"
- A diff step that's obvious to read: new entries clearly marked, nothing
  buried in noise.
- It should not crash if `subfinder` isn't installed, if the network
  hiccups, or if a domain has zero results, it should fail loudly with a
  clear message, not with a raw traceback.

## The prompt

```
I'm building a Python-based reconnaissance toolkit for authorized
security engagements. I need a script built around the subfinder CLI
tool (invoked via subprocess) that does subdomain enumeration AND
ongoing subdomain monitoring. This is for domains I am explicitly
authorized to test, as part of a scoped engagement.

Requirements:

1. Accept one or more root domains as input, either as command-line
   arguments (argparse) or as a file with one domain per line
   (-l/--list style flag).

2. For each domain, invoke subfinder as a subprocess with sensible
   defaults (silent output, JSON output if subfinder's -oJ flag is
   available so it's easy to parse) and save the results to a
   per-domain JSON or text file under a results directory, structured
   like:
   results/<domain>/<domain>_YYYYMMDD_HHMMSS.json

   Also maintain results/<domain>/latest.json as a copy of the most
   recent run's parsed subdomain set, so later steps always have an
   easy "current state" to read without re-parsing timestamped files.

3. Add a "monitor" mode that:
   - Runs subfinder again for a given domain (or all domains previously
     enumerated, tracked in a small state file so I don't have to
     re-specify them every time).
   - Diffs the new result (as a Python set) against the previous
     latest.json.
   - Prints a clearly labeled "NEW SUBDOMAINS FOUND" section if anything
     appeared that wasn't there last time, and a "REMOVED" section if
     anything disappeared (useful signal too, e.g. decommissioned
     services).
   - If nothing changed, say so explicitly rather than printing nothing
     (I want to know the check ran, not just that it found nothing).
   - Appends any new subdomains found to a running
     results/<domain>/new_subdomains_log.jsonl (one JSON object per
     line, with a timestamp), so I have a full history of when each
     subdomain first appeared, not just the latest diff.

4. Make monitor mode usable both as a one-shot check (I call it manually
   or from cron/Task Scheduler) and as a long-running loop with a
   configurable interval in seconds (--interval 3600 to check hourly).
   Use a plain time.sleep loop with clean Ctrl+C (KeyboardInterrupt)
   handling rather than pulling in a heavier scheduling dependency.

5. Handle these failure cases gracefully with clear error messages, not
   raw tracebacks:
   - subfinder is not installed or not on PATH (tell me exactly how to
     install it: "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
   - a domain returns zero subdomains
   - the results directory doesn't exist yet on first run (create it)
   - subfinder's subprocess call returns a non-zero exit code or times out
     (add a reasonable subprocess timeout so one hung domain can't stall
     a monitoring loop across many domains forever)

6. Normalize output before diffing/storing: lowercase everything, strip
   any trailing dots, and store as a Python set so dedup is automatic
   and the diff logic (set difference) stays simple and correct.

7. Print a short summary at the end of every run: how many subdomains
   total, how many new since last run, how long the enumeration took
   (use time.perf_counter, not wall-clock time.time, for the duration
   measurement).

8. Add a top-of-file docstring reminding whoever runs this that it must
   only be pointed at domains they are explicitly authorized to test,
   since subdomain enumeration is reconnaissance against someone else's
   infrastructure even when it uses only public data sources.

Write it with a clear separation between the subfinder-invocation layer,
the state/diffing logic, and the reporting/output layer, so I can extend
it later (e.g. wiring the "new subdomains found" event to a Slack or
Discord webhook via a simple requests.post call) without touching the
core enumeration logic.
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
