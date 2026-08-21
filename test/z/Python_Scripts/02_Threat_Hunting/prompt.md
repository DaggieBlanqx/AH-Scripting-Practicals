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

The catch: **you cannot `cat` a pcap.** There is no `samples/` excerpt to
skim this time, no plaintext log to grep by eye. Everything you need is
inside packet captures, and the only way in is to actually parse them.

## Why this activity has no sample file

Every other activity in this course ships a small `samples/*.log` excerpt
so you can eyeball the attack before writing code. A PCAP does not work
that way; opening it in a text editor gives you binary noise, not a
story. That is the whole point of this exercise: you have to prompt an
AI (or write the code yourself) to build the tool that turns packets into
a narrative, before you can read the narrative at all.

## Your mission

Open `pcap/atlas_continental_ransomware_incident.pcap` with a proper tool
(scapy is the natural choice in Python) and reconstruct the full timeline:

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
incident at a company called Atlas Continental Corporation. I cannot open
it as text, so I need you to write me a Python script (using scapy) that
reads the pcap and reconstructs the incident as a readable report.

Specifically, the script should:
1. Load the pcap and print how many packets it contains and the time
   span it covers.
2. Find any SMTP traffic (port 25) and extract the sender, subject, and
   any attachment filename mentioned in the message - this is probably
   the initial phishing delivery.
3. Find DNS queries and flag any domains that look like they could be
   C2 infrastructure (recently-registered-sounding, generic CDN-style
   names, etc.), and count how many distinct internal hosts queried them.
4. Look for repeated small HTTP POST requests to the same external host
   at regular intervals from many different internal IPs - that is
   probably C2 beaconing / lateral spread, so group and count it by
   internal subnet if the IPs suggest different office networks.
5. Find any unusually large or repeated outbound data transfers to a
   single external IP and report the destination and an estimate of
   what was sent (look for any manifest-style text at the start of
   the payload).
6. Search all packet payloads for anything that looks like a ransom
   note (keywords like "encrypted", "bitcoin", "ransom", "decrypt") and
   print the full text if found.
7. Find the longest-lived TCP session in the capture, reconstruct its
   payload in chronological order, and print it as a conversation - this
   is likely a negotiation chat between the victim and the attacker.
   Tell me how many messages it contains and how many days it spans.
8. Search for anything that looks like a cryptocurrency transaction ID
   or wallet address, and anything that looks like a decryption key
   being handed over in the chat.
9. This is the important part: check whether any host that was
   beaconing earlier in the capture is STILL beaconing to a DIFFERENT
   external IP after the negotiation/decryption appears to have
   finished. Flag this loudly as a possible persistent backdoor, even
   if the rest of the incident looks resolved.
10. Print a clear, section-by-section summary to the console.

Also generate a professional PDF incident report from the findings, with
a title page, a one-line severity banner, an executive summary table, one
section per finding above, and a simple bar chart of infected hosts per
office. If a PDF library isn't installed, have the script install it
automatically with pip the first time it runs so I don't have to set
anything up by hand.
```

## After you get a script

Run it against `pcap/atlas_continental_ransomware_incident.pcap` and
compare your findings against `scripts/analyze_ransomware_pcap.py`, the
reference script for this activity. Yours does not need to match it line
for line, it needs to tell the same true story: who got in, what left,
what was paid, and whether it is really over.

Pay particular attention to finding #9. In real incidents, that is the
detail that gets missed under deadline pressure, and it is exactly the
kind of thing a good threat hunter is paid to catch.
