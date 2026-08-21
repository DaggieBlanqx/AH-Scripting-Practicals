# RECON TASKING: OPERATION OPEN DOOR

```
FROM:     Engagement Lead
TO:       Recon Operator (you)
SUBJECT:  Port and service discovery across a mixed target list
TOOLING:  nmap, Python
PRIORITY: Turns a list of names into a list of doors
```

Operation First Light gave you a pile of domains, subdomains, and maybe a
few raw IPs handed to you directly by the client. A hostname on its own
tells you nothing about what's actually running behind it. This phase
answers the question that actually matters to an attacker: **what's
listening, and what is it?**

An open port is a door. A door with a version banner on it is a door
with a sign on it telling you what's behind it. That's what you're
hunting for now.

## Your mission

Build a Python script around `nmap` that accepts a **mixed** target list,
domains, subdomains, and IP addresses/CIDR ranges all in the same input,
and produces one clean, structured report of open ports, the services
running on them, and their versions where nmap can determine them.

## Before you prompt the AI

Think about the shape of your real input before you start: it's probably
the `latest.json` files Operation First Light produced, maybe combined
with a client-provided IP range. Your script needs to accept that mess
and make sense of it, not assume a single tidy format. Also decide up
front whether you want to shell out to nmap via `subprocess` and parse
its XML output yourself (more control, no extra dependency) or use the
`python-nmap` library (less code, one more thing to auto-install), the
prompt below leaves that choice to the AI but asks it to justify the
pick.

## The prompt

```
I'm building a Python-based reconnaissance toolkit for authorized
security engagements. I need a script that takes a mixed list of
domains, subdomains, and IP addresses (including CIDR ranges), resolves
what needs resolving, and runs nmap against all of it to find open ports
and identify the services/versions running on them. This is for hosts I
am explicitly authorized to test, as part of a scoped engagement.

Requirements:

1. Accept input as command-line arguments and/or a file (-l/--list),
   with one target per line. A single input file might contain a mix of:
   - root domains (example.com)
   - subdomains (api.example.com, staging.example.com)
   - bare IPv4 addresses (203.0.113.5)
   - CIDR ranges (203.0.113.0/24)
   Use Python's `ipaddress` module to reliably detect IPs/CIDRs versus
   hostnames (don't rely on a fragile regex for this part, ipaddress
   will parse-or-raise cleanly).

2. For every hostname target, resolve it to its IP address(es) first
   (socket.gethostbyname_ex or dnspython if you prefer more control),
   and:
   - Keep a mapping of hostname -> resolved IP(s) so the final report can
     show both, not just a bare IP with no context.
   - Deduplicate the final IP target list before scanning, since many
     subdomains often share one IP (a CDN, a load balancer, a WAF). Flag
     in the report when multiple input hostnames resolved to the same
     IP, that's useful intel on its own (shared infrastructure).
   - Skip and clearly log any hostname that fails to resolve (catch
     socket.gaierror specifically), don't let one bad DNS lookup kill
     the whole run.

3. Run nmap against the deduplicated IP list with service/version
   detection (-sV) and default script scan where reasonable (-sC), using
   a timing template that's a sane default for an authorized engagement
   (-T3), with an option to override timing via a flag for slower/careful
   scans against sensitive or small targets. Explain in a comment
   whether you chose to shell out via subprocess + XML parsing
   (xml.etree.ElementTree) or the python-nmap library, and why.

4. Support two scan depths via a flag: a fast "top ports" pass (nmap
   --top-ports, e.g. 100 or 1000) for quick triage across a big target
   list, and a "full" pass (-p-) for when I want to be thorough about a
   specific host. Default to the fast pass so a big target list doesn't
   take forever by accident.

5. Parse nmap's XML output into Python data structures (dataclasses or
   plain dicts, your call) and produce a clean, structured summary
   report showing, per host:
   - hostname(s) that resolved to it, if any
   - open port, protocol, service name, version string if detected
   - Group and sort the report by host, most-open-ports first, so the
     juiciest targets are at the top.

6. Add a "notable findings" section at the end of the report that
   specifically flags:
   - Any of these historically higher-risk services if found open:
     FTP (21), Telnet (23), unencrypted admin-style ports, SMB (445),
     RDP (3389), or any database port (3306, 5432, 1433, 27017, 6379)
     exposed directly to the internet.
   - Any service where nmap could not positively identify a version
     (worth manual follow-up).

7. Handle these failure cases gracefully with clear messages:
   - nmap not installed (catch FileNotFoundError from subprocess and
     tell me how to install it: apt/brew/pkg install command)
   - a target that isn't a valid IP, CIDR, or resolvable hostname
   - nmap requiring elevated privileges for certain scan types, and a
     clear message about what to do if it's not run with enough
     privilege for -sS/OS detection
   - an empty or malformed input file
   - subprocess timeout on a target that hangs (set a reasonable
     per-target timeout so one bad host doesn't stall the whole run)

8. Save both the raw nmap XML output (for later re-parsing or feeding
   into other tools) and the final human-readable report, timestamped,
   under a results directory.

9. Add a top-of-file docstring reminding whoever runs this that scanning
   infrastructure without explicit authorization is illegal in most
   jurisdictions, and that even authorized scans should respect any
   timing/scope constraints agreed with the client, since aggressive
   scanning can disrupt fragile or rate-limited services.

Structure the code so target parsing, resolution, scanning, and
reporting are clearly separate functions/classes, so I could later swap
in a different scan tool or add a step that feeds this report into
something else (like generating a PDF, similar to how the log analysis
activity in this course auto-installs fpdf2 and renders a report).
```

## After you get a script

Feed it a small file mixing a domain you're authorized to test, one of
its subdomains, and a raw IP or two. Confirm the resolution step
correctly groups hostnames that share an IP, and that the notable
findings section actually catches something when you point it at a
target you know has an interesting port open (stand up a throwaway VM
with something listening on an unusual port if you need a clean test).
