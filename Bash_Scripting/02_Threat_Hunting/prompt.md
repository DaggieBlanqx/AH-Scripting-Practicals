# INCIDENT RESPONSE TASKING: Operation GENTLEMEN'S HANDSHAKE

```
FROM:    Atlas Continental Corporation - Global SOC
TO:      Incoming DFIR Analyst (you)
SUBJECT: Full kill-chain reconstruction requested
PRIORITY: CRITICAL
ATTACHMENT: atlas_continental_ransomware_incident.pcap
```

You've just been looped into a live incident. A ransomware crew calling
themselves **The Gentlemen** put roughly 5,000 endpoints across six
offices on ice, walked out with an enormous amount of company data, left
a note, negotiated for three days over a Tor bridge, got paid, handed
back a key, and (allegedly) left. Legal, the board, and a very tired CISO
want a single document that explains exactly what happened, in order,
with receipts.

The catch: **you cannot `grep` a pcap the way you grep a log file.** There
is no `samples/` excerpt to skim this time, no plaintext file to eyeball.
Everything you need is inside packet captures, in binary framing, and
the only way in is through a real packet-parsing tool.

## Why this activity has no sample file

Every other activity in this course ships a small `samples/*.log` excerpt
so you can eyeball the attack before writing code. A PCAP does not work
that way; `cat`-ing it gives you binary noise, not a story. That is the
whole point of this exercise: you have to prompt an AI (or write the
tooling yourself) to turn packets into a narrative before you can read
the narrative at all. In this activity, Bash's role is to drive
`tshark`/`tcpdump` for the field-extraction and quick filtering you know
from `grep`/`awk`/`sed`, and to hand the heavy lifting (protocol parsing,
report rendering) to a small Python helper, exactly the way a real SOC
shell script orchestrates specialist tools it doesn't reimplement itself.

## Your mission

Point `tshark` (or `tcpdump`) at
`pcap/atlas_continental_ransomware_incident.pcap` and, through Bash text
processing, reconstruct the full timeline:

1. **Initial access** - find the phishing email and the malicious attachment
2. **Detonation & C2** - the domain the malware called home to, and the beacon pattern
3. **Lateral spread** - which offices got infected, and roughly when
4. **Exfiltration** - what left the building, to where, and what it was
5. **Encryption & the ransom note** - the demand, the deadline, the wallet
6. **The negotiation** - reconstruct the actual back-and-forth chat
7. **Payment** - the transaction, the confirmations
8. **The decryption key** - did they actually hand one over?
9. **The part everyone forgets** - did the attacker really leave, or is
   something still quietly phoning home after the "resolution"?

## The prompt

Copy this into your AI assistant of choice. Swap in details as you
discover them; the more specific you get after your first pass, the
better the second pass will be.

```
I'm doing a DFIR exercise. I have a PCAP file called
atlas_continental_ransomware_incident.pcap from a fictional ransomware
incident at a company called Atlas Continental Corporation. I want to
analyze it primarily with Bash, using tshark as the packet-parsing engine
and grep/awk/sed/sort/uniq the way I would with a text log, but calling
out to a small Python helper (scapy + a PDF library) for anything Bash
genuinely can't do well, like full TCP stream reassembly and rendering a
PDF.

Please write me:

1. A Bash script that uses `tshark -r <pcap>` to:
   - Print the protocol hierarchy (io,phs) so I know what's actually in
     the capture.
   - Extract all SMTP traffic (port 25) and pull out the sender,
     subject, and any attachment filename - this is probably the
     initial phishing delivery.
   - Extract all DNS queries (`-Y "dns.flags.response==0"`) and count
     them by domain and by source IP, so I can spot a command-and-control
     domain being queried by many internal hosts across different
     subnets (which would suggest infected offices, not just one host).
   - Extract HTTP requests and flag any repeated, near-identical POST
     requests to the same external host at regular intervals - that's
     likely C2 beaconing.
   - Flag any single external destination receiving an unusually large
     number of bytes or packets from internal hosts - likely
     exfiltration - and pull out any readable manifest-style text in
     those payloads.
   - Search all extracted ASCII strings for ransom-note keywords
     ("encrypted", "bitcoin", "ransom", "decrypt") and print the full
     note if found.
   - Identify the single longest-duration TCP conversation in the
     capture (`tshark -z conv,tcp`) as a likely candidate for a
     negotiation chat.

2. A Python helper script (auto-installing scapy and a PDF library like
   fpdf2 with pip if they're missing, so I don't have to set anything up
   by hand) that the Bash script calls at the end to:
   - Fully reconstruct that longest TCP conversation in chronological
     order and print it as a readable back-and-forth chat, with a
     message count and how many days it spans.
   - Pull out anything that looks like a cryptocurrency transaction ID
     or wallet address, and any decryption key handed over in the chat.
   - This is the important part: check whether any host that was
     beaconing earlier in the capture is STILL beaconing to a DIFFERENT
     external destination after the negotiation/decryption appears to
     have finished, and flag it loudly as a possible persistent
     backdoor even if the rest of the incident looks resolved.
   - Generate a professional PDF incident report: a title page, a
     one-line severity banner, an executive summary table, one section
     per finding above, a simple bar chart of infected hosts per office,
     and the full negotiation chat transcript.

Make the Bash script gracefully skip the tshark-only sections (with a
clear message telling me to install Wireshark) if tshark isn't
installed, but still hand off to the Python helper either way, since
that part only needs scapy.
```

## After you get a script

Run it against `pcap/atlas_continental_ransomware_incident.pcap` and
compare your findings against `scripts/analyze_ransomware_pcap.sh` (and
its companion `analyze_ransomware_pcap.py`), the reference scripts for
this activity. Yours does not need to match them line for line, it needs
to tell the same true story: who got in, what left, what was paid, and
whether it is really over.

Pay particular attention to finding #9. In real incidents, that is the
detail that gets missed under deadline pressure, and it is exactly the
kind of thing a good threat hunter is paid to catch.
