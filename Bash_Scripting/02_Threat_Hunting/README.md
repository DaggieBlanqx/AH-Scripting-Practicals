# Activity 2: Threat Hunting (Bash)

This activity is different from Activity 1 on purpose. There is no text
log to open and read here. There is exactly one file that matters:
`pcap/atlas_continental_ransomware_incident.pcap`. Every single fact you
need, the phishing email, the malware, the lateral spread across six
offices, the exfiltration, the ransom note, the three-day negotiation
chat, the payment, the decryption key, and the backdoor left behind
afterward, is captured inside that network traffic. Nothing about the
incident exists outside of it. If you can read the packets, you can
reconstruct the entire story from first contact to (apparent) resolution.

None of the companies, IPs, domains, wallet addresses, chat handles, or
people in this capture are real. Nothing in it resolves or is reachable.
It was generated for training purposes only.

## Folder layout

```
02_Threat_Hunting/
  pcap/       the incident capture (atlas_continental_ransomware_incident.pcap)
  prompt.md   a mission-style prompt you can hand an AI assistant to build your own analyzer
  README.md   this file
```

## The scenario is the pcap

**Atlas Continental Corporation**, a fictional multinational with offices
in Chicago (HQ), Dubai, New York, Auckland, Berlin, and Johannesburg, was
hit by a ransomware group calling itself **The Gentlemen**. Everything
below is *reconstructed directly from the packet capture*, not narrated
separately from it, because that is the entire point of this activity:
a PCAP is a complete, literal record of what happened on the wire.

1. **Initial access** is a spear-phishing email, spoofed to look like it
   came from HR, subject line *"Confidential: 2026 Salary Increase
   Notification"*, with an attachment named `SalaryIncrease.pdf.exe` (a
   PDF icon hiding a real `.exe`, the classic double-extension trick).
   You can read the full SMTP conversation, sender, subject, and
   attachment name, directly out of the capture.
2. **Detonation and command-and-control**: opening the attachment
   triggers a DNS lookup for the attacker's C2 domain and a beacon
   channel, both fully visible as DNS and HTTP traffic in the pcap.
3. **Lateral spread**: over roughly 30 hours, representative hosts across
   all six office networks check in with the C2 server, each beacon
   carrying the hostname and office in plain text. The pcap holds a
   sampled subset of hosts; the organization's own asset inventory puts
   the true scope at roughly 5,000 endpoints, since no real capture
   records full packet data for every endpoint in an estate that size.
4. **Exfiltration**: before encryption, a declared 600 TB of data
   (financial records, the customer database, source code, HR/PII
   records, and engineering archives) is staged and sent out. The
   capture holds manifest headers naming exactly what categories of data
   left the building and to where.
5. **Encryption and the ransom note**: all six offices are hit with mass
   encryption, and a ransom note is dropped on every file share. The
   full note text, the exact ransom figure ($5,000,000 in Bitcoin), the
   wallet address, and the 5-day deadline are all sitting in the
   traffic in plain text.
6. **The negotiation**: this is the part that makes this pcap special.
   The entire three-day, 24-message back-and-forth between the IR team
   and The Gentlemen happened over a channel that is fully reconstructible
   from the capture, message by message, timestamp by timestamp, exactly
   like following a TCP stream in a packet analyzer. You can watch the
   ransom get talked down from $5,000,000 to $1,250,000 in real time.
7. **Payment and the key**: the Bitcoin transaction ID, the confirmation
   count, and the actual decryption key handed over in chat are all
   recoverable from the traffic.
8. **The twist**: the attacker claims to "destroy our copy" of the data
   and the incident looks resolved, but the capture keeps going. Two
   hosts continue quietly beaconing to a second, previously undisclosed
   command-and-control address for at least two more days afterward.
   That detail, easy to miss if you stop analyzing the moment the chat
   sounds like it's over, is the single most important finding in this
   entire exercise.

## How to use this activity

1. Read `prompt.md` first. It frames the mission and gives you a full,
   ready-to-use prompt for asking an AI assistant to build a Bash +
   `tshark` script (with a small amount of hex-decoding via `xxd` for
   the parts that need it) that reconstructs the incident from the pcap.
2. Try that prompt, or write the analysis yourself. Either way, the goal
   is a script that walks through the whole kill chain: initial access,
   C2, lateral spread, exfiltration, the ransom note, the negotiation
   chat, the payment, the decryption key, and the backdoor, and that
   also renders a PDF incident report.
3. Run your script against
   `pcap/atlas_continental_ransomware_incident.pcap` and see whether it
   reconstructs the same story described above. If your script cannot
   find something on this list, look harder at the capture, it is in
   there.

## A note on scale and realism

A real ransomware incident across 5,000 endpoints and 600 TB of data
would produce a capture far too large to ship in a training repository.
This pcap instead holds a representative sample per office and a
manifest-style summary of what was exfiltrated, exactly the way a real
DFIR team works from key chokepoints and EDR telemetry rather than
full-packet capture of every single endpoint. Everything else, every
message, every timestamp, every IP address, is real network traffic in
this file, not a summary of it.
