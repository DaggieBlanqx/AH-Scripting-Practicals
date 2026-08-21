# AH Scripting Practicals

A hands on cybersecurity scripting course built around real incidents,
not toy examples. Every activity here drops you into a fictional but
richly detailed breach, the kind a SOC analyst, an incident responder,
or a red teamer would actually face, and asks you to script your way
through it. Nothing about the companies, people, IPs, domains, or wallet
addresses in this repository is real.

The course is split into two parallel tracks so you can practice the
same skills in either language.

```
AH-Scripting-Practicals/
  Bash_Scripting/
    01_Log_Analysis/
    02_Threat_Hunting/
    03_Recon/
  Python_Scripting/
    01_Log_Analysis/
    02_Threat_Hunting/
    03_Recon/
```

Pick a track, work through the three activities in order, and use an AI
assistant the way a working analyst would: as a tool that writes the
first draft of a script so you can spend your energy on reading the
data, spotting the pattern, and judging whether the output is actually
right.

## Activity 1: Log Analysis

Five text logs, five fictional companies, five real world attack
patterns. Each log is 2,500 lines long: roughly 1,500 lines of ordinary,
everyday traffic and about 1,000 lines of an attack, interleaved
chronologically the way a real production log would be. Nothing is
handed to you in isolation. You have to filter the signal out of the
noise.

A short excerpt of each log, centered on the interesting part, lives
alongside the full version so you have something readable to start from
before you turn an AI assistant loose on the whole file.

| Company | What happened |
|---|---|
| Meridian Retail Group | SQL injection recon, blind extraction, and UNION based data dumps, followed by an authentication bypass and stolen customer accounts |
| Vantage Cloud Systems | A JNDI style injection and a disguised file upload lead to a webshell, then a full server takeover and outbound command and control traffic |
| Kestrel Manufacturing Corp | A leaked token dump is used to script a bulk privilege escalation attack, creating rogue admin accounts and committing payroll fraud |
| Bazario Marketplace | A reseller ring exploits client side price tampering to buy items worth thousands of dollars for a few cents each |
| Solstice Health Networks | Credential stuffing against real usernames succeeds on a shared service account, leading to lateral movement and a stolen patient database |

Every one of these five incidents traces back to a well known, well
documented class of security mistake: injection, a vulnerable component,
broken access control, and authentication failures without rate limiting
or multi factor authentication. Recognizing the pattern in the logs is
half the exercise. Understanding why it worked is the other half.

## Activity 2: Threat Hunting

One network packet capture, one company, one full ransomware incident
from first contact to the aftermath. There is no text log here on
purpose: a PCAP cannot be skimmed the way a log file can, so this
activity is about learning to pull a story out of raw network traffic
instead of being handed one.

The scenario: Atlas Continental Corporation, a fictional multinational
with offices in Chicago, Dubai, New York, Auckland, Berlin, and
Johannesburg, is hit by a ransomware group calling itself The Gentlemen.
A spear phishing email delivers a dropper disguised as a salary notice.
The malware calls home, spreads across representative hosts in every
office, and exfiltrates a declared 600 terabytes of company data before
encrypting everything and dropping a ransom note demanding five million
dollars in Bitcoin. What follows is fully reconstructable straight out
of the packet capture: a three day, back and forth negotiation over a
dark web channel that talks the price down to 1.25 million dollars, the
Bitcoin transaction, and the decryption key finally handed over.

Then the capture keeps going. Two hosts quietly keep phoning home to a
second, previously undisclosed address for two more days after the
attackers claim to have walked away. Catching that detail, after
everyone else has decided the incident is over, is the real point of
this activity.

## Activity 3: Recon

Reconnaissance is not something you can practice against a sample file,
since it means actively probing real infrastructure. So this activity
works differently from the first two: instead of a ready made log or
capture, you get three detailed mission style prompts that walk you
through building your own reconnaissance tooling with an AI assistant,
one capability at a time.

1. Subdomain enumeration and continuous monitoring, built around
   subfinder, so you can catch new attack surface the moment it appears
   instead of finding out about it during a scheduled scan.
2. Port and service discovery across a mixed list of domains,
   subdomains, and IP ranges, built around nmap, turning a list of names
   into a list of open doors and the services listening behind them.
3. Leaked credential discovery across a GitHub organization or
   repository, including full commit history, with one rule that matters
   above all the rest: forked repositories must always be excluded from
   the scan.

Every prompt in this activity produces a script that acts on real, live
infrastructure using genuine offensive security tooling. Only ever point
what you build at systems, domains, or repositories you own or are
explicitly authorized to test.

## A word on the data

Every log, every packet capture, and every scenario in this repository
was generated for training purposes only. The companies do not exist,
the people are not real, the IP addresses and domains do not resolve,
and the Bitcoin wallet address will not receive your money. Treat the
realism as a teaching tool, not as a template for anything outside this
course.
