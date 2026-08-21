# Activity 3: Recon (Bash)

This activity is different from Activities 1 and 2 on purpose. There is
no log to parse and no pcap to reconstruct here, because reconnaissance
isn't something you analyze after the fact, it's something you actively
run against live infrastructure. That means there is no safe, pre-baked
sample data to ship in this repository. Instead, this folder gives you
three detailed, ready-to-use prompts for building your own recon tooling
with an AI assistant.

## Folder layout

```
03_Recon/
  prompt1.md   Subdomain enumeration + continuous monitoring (subfinder)
  prompt2.md   Port and service discovery across domains, subdomains, and IPs (nmap)
  prompt3.md   Leaked credential discovery across a GitHub org or repo (git + GitHub API)
  README.md    this file
```

These three prompts follow the natural order of a real reconnaissance
phase: find the attack surface, find what's listening on it, and check
whether anyone already leaked the keys to it on GitHub.

## Before you touch any of these

Every prompt in this folder produces a script that acts on real,
external infrastructure using real offensive-security tools (`subfinder`,
`nmap`, live GitHub API calls, and full repository clones). Every one of
them carries the same non-negotiable rule:

**Only ever point these at domains, IP ranges, or GitHub
organizations/repositories you own outright or are explicitly authorized
to test.** Unauthorized scanning and reconnaissance against systems you
don't have permission to assess is illegal in most jurisdictions and is
outside the scope of what this course teaches. Each prompt bakes an
authorization reminder into the script it asks the AI to generate; keep
that comment block in whatever you build, don't strip it out.

## How to use this activity

1. Open `prompt1.md`, read the mission framing, and copy the prompt block
   inside it into an AI assistant.
2. Take the script you get back, run it against a domain you're
   authorized to test (a personal domain, a lab environment, or an
   in-scope bug bounty target), and check the output actually makes
   sense: does the monitoring/diff logic really catch a new subdomain
   when one appears?
3. Move to `prompt2.md`. Feed your new script the output from step 2 (or
   a small hand-built mixed list of domains/subdomains/IPs) and confirm
   it produces a clean port/service report with the notable-findings
   section actually flagging something when you test it against a host
   you know has an interesting port open.
4. Move to `prompt3.md`. Test it against a throwaway GitHub org you
   control that has at least one forked repo, and confirm the fork gets
   excluded (and the exclusion is visible in the output, not just
   silent). Then prove the history-scanning actually works by committing
   a fake secret, deleting it in a later commit, and confirming your
   script still finds it.

There is no reference script or "answer key" for this activity. Recon
tooling only means something when it's pointed at a target, and picking
a safe, realistic target to ship in a training repository isn't
possible the way it was for the log and pcap activities. Your AI
assistant's output, tested against something you're authorized to scan,
is the deliverable here.

## What each prompt is really teaching

- **prompt1 (subfinder)**: that recon isn't a one-time snapshot. Attack
  surface changes constantly, and the organizations that get breached
  through a forgotten subdomain are usually the ones who only looked
  once.
- **prompt2 (nmap)**: that a hostname means nothing until you know what's
  actually listening behind it, and that shared infrastructure (many
  subdomains resolving to one IP) is itself useful intelligence.
- **prompt3 (GitHub)**: that "public" and "supposed to be secret" are not
  the same thing, that deleted history isn't actually deleted, and that
  correctly excluding forked repositories is the difference between a
  finding that matters and one that's attributed to the wrong company
  entirely.
