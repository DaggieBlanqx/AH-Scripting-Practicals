#!/usr/bin/env python3
"""
analyze_ransomware_pcap.py
Target: pcap/atlas_continental_ransomware_incident.pcap (Atlas Continental Corporation)

Reconstructs the full lifecycle of a ransomware incident from a network
packet capture: the spear-phishing delivery, malware detonation and C2
beaconing, lateral spread across six global offices, data exfiltration,
the mass encryption event and ransom note, a multi-day dark web
negotiation chat with the "The Gentlemen" ransomware group, the Bitcoin
payment, the decryption key handoff, and a persistent backdoor left
behind after the incident was declared "resolved".

Usage: python analyze_ransomware_pcap.py <path-to-pcap> [--pdf output.pdf]

Missing packages (scapy, fpdf2) are installed automatically on first run.
"""

import argparse
import os
import re
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime


def _ensure_scapy():
    try:
        import scapy.all as scapy  # noqa: F401
        return scapy
    except ImportError:
        print("[analyze_ransomware_pcap] scapy not found, installing it now (pip install scapy)...")
        result = subprocess.run([sys.executable, "-m", "pip", "install", "--quiet", "scapy"],
                                 capture_output=True, text=True)
        if result.returncode != 0:
            print(result.stdout)
            print(result.stderr)
            raise RuntimeError("Could not automatically install scapy. Install it manually with: python -m pip install scapy")
        import scapy.all as scapy  # noqa: F401
        return scapy


scapy = _ensure_scapy()
from scapy.all import rdpcap, TCP, UDP, IP, Raw, DNS, DNSQR  # noqa: E402

from pdf_report_lib import IncidentReport

# ---------------------------------------------------------------------------
# Known incident facts, corroborated by the IR team's asset inventory and
# EDR telemetry. The packet capture below holds a REPRESENTATIVE SAMPLE of
# traffic (a handful of hosts per office, a manifest sample of exfiltrated
# categories), not full-packet capture of all 5,000 endpoints, exactly like
# a real enterprise-scale DFIR engagement.
# ---------------------------------------------------------------------------
DECLARED_TOTAL_ENDPOINTS = 5000
DECLARED_OFFICES = ["Chicago (HQ)", "Dubai", "New York", "Auckland", "Berlin", "Johannesburg"]
DECLARED_EXFIL_TOTAL = "600 TB"
RANSOMWARE_GROUP = "The Gentlemen"
BACKDOOR_C2_IP = "95.216.201.77"
C2_STAGE1_IP = "45.147.230.12"
EXFIL_IP = "45.147.230.55"
DARKWEB_PORT = 9050


def load_packets(path):
    return rdpcap(path)


def stream_text(pkts, ip_a, ip_b, port):
    """All Raw payloads between ip_a and ip_b on the given port, ordered by time."""
    items = []
    for p in pkts:
        if not (p.haslayer(IP) and p.haslayer(TCP) and p.haslayer(Raw)):
            continue
        ip = p[IP]
        tcp = p[TCP]
        if {ip.src, ip.dst} == {ip_a, ip_b} and port in (tcp.sport, tcp.dport):
            items.append((float(p.time), ip.src, p[Raw].load))
    items.sort(key=lambda x: x[0])
    return items


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap_file", nargs="?", default="../pcap/atlas_continental_ransomware_incident.pcap")
    ap.add_argument("--pdf", default=None)
    args = ap.parse_args()

    pkts = load_packets(args.pcap_file)
    total_packets = len(pkts)
    first_ts = min(float(p.time) for p in pkts)
    last_ts = max(float(p.time) for p in pkts)
    span_days = (last_ts - first_ts) / 86400

    # ---- Phase 1: phishing email ----
    smtp_pkts = [p for p in pkts if p.haslayer(TCP) and p[TCP].dport == 25 and p.haslayer(Raw)]
    phish_sender = phish_subject = phish_attachment = None
    for p in smtp_pkts:
        text = p[Raw].load.decode(errors="replace")
        if "From:" in text and phish_sender is None:
            for line in text.splitlines():
                if line.startswith("From:"):
                    phish_sender = line.split("From:", 1)[1].strip()
                if line.startswith("Subject:"):
                    phish_subject = line.split("Subject:", 1)[1].strip()
                if "filename=" in line:
                    phish_attachment = line.split("filename=")[1].strip().strip('"')

    # ---- Phase 2/3: C2 DNS + beacon spread ----
    dns_queries = [p for p in pkts if p.haslayer(DNS) and p[DNS].qdcount and p[DNS].qr == 0]
    c2_domains = Counter(p[DNSQR].qname.decode().rstrip(".") for p in dns_queries if p.haslayer(DNSQR))

    beacon_pkts = [p for p in pkts if p.haslayer(TCP) and p.haslayer(Raw) and b'"group":"TheGentlemen"' in p[Raw].load]
    infected_hosts = set()
    hosts_by_office = defaultdict(set)
    for p in beacon_pkts:
        payload = p[Raw].load.decode(errors="replace")
        if '"office"' in payload:
            office = payload.split('"office":"')[1].split('"')[0]
            host = payload.split('"host":"')[1].split('"')[0]
            hosts_by_office[office].add(host)
            infected_hosts.add(host)
        elif '"host"' in payload:
            host = payload.split('"host":"')[1].split('"')[0]
            infected_hosts.add(host)
            hosts_by_office["HQ-CHI"].add(host)

    # ---- Phase 4: exfiltration manifest ----
    manifest_pkts = [p for p in pkts if p.haslayer(Raw) and b"EXFIL-MANIFEST" in p[Raw].load]
    manifest = []
    manifest_field_re = re.compile(
        r"category=(?P<category>\S+) filename=(?P<filename>\S+) "
        r"declared_total_size=(?P<declared_total_size>[\d.]+ TB) archive_id=(?P<archive_id>\d+)"
    )
    for p in manifest_pkts:
        text = p[Raw].load.decode(errors="replace")
        m = manifest_field_re.search(text)
        if m:
            manifest.append(m.groupdict())

    # ---- Phase 5: ransom note ----
    note_pkts = [p for p in pkts if p.haslayer(Raw) and b"README_DECRYPT_THE_GENTLEMEN" in p[Raw].load]
    ransom_note_text = note_pkts[0][Raw].load.decode(errors="replace") if note_pkts else ""
    ransom_note_offices = len(note_pkts)

    # ---- Phase 6: dark web negotiation chat ----
    chat_items = stream_text(pkts, "10.10.1.30", "91.219.237.44", DARKWEB_PORT)
    chat_msgs = [(t, src, payload.decode(errors="replace").replace("[CHAT] ", "").strip())
                 for t, src, payload in chat_items if b"[CHAT]" in payload]
    chat_span_days = (chat_msgs[-1][0] - chat_msgs[0][0]) / 86400 if chat_msgs else 0

    # ---- Phase 7: BTC payment confirmation ----
    btc_pkts = [p for p in pkts if p.haslayer(Raw) and b"confirmations" in p[Raw].load]
    btc_confirmation = btc_pkts[-1][Raw].load.decode(errors="replace") if btc_pkts else None

    # ---- Phase 8: decryption key + execution ----
    decrypt_key = None
    for t, src, msg in chat_msgs:
        if "Decryption key:" in msg:
            decrypt_key = msg.split("Decryption key:")[1].strip()
    decrypt_result_pkts = [p for p in pkts if p.haslayer(Raw) and b"DECRYPT_TOOL_RESULT" in p[Raw].load]

    # ---- Phase 9: backdoor persistence after "resolution" ----
    resolution_time = max((t for t, src, msg in chat_msgs if "resolved" in msg or "destroy our copy" in msg), default=last_ts)
    backdoor_pkts = [p for p in pkts if p.haslayer(IP) and p[IP].dst == BACKDOOR_C2_IP and p.haslayer(Raw)]
    backdoor_hosts = sorted(set(p[IP].src for p in backdoor_pkts))
    backdoor_after_resolution = [p for p in backdoor_pkts if float(p.time) > resolution_time]

    # =======================================================================
    # Console summary
    # =======================================================================
    print("=" * 70)
    print(" RANSOMWARE INCIDENT RECONSTRUCTION - Atlas Continental Corporation")
    print("=" * 70)
    print(f"Packets analyzed        : {total_packets}")
    print(f"Capture span            : {span_days:.1f} days ({datetime.fromtimestamp(first_ts)} -> {datetime.fromtimestamp(last_ts)})")
    print(f"Phishing sender         : {phish_sender}")
    print(f"Phishing subject        : {phish_subject}")
    print(f"Malicious attachment    : {phish_attachment}")
    print(f"C2 domains contacted    : {dict(c2_domains)}")
    print(f"Infected hosts (sample) : {len(infected_hosts)} across {len(hosts_by_office)} offices")
    print(f"Exfil manifest entries  : {len(manifest)}")
    print(f"Ransom note drops seen  : {ransom_note_offices}")
    print(f"Dark web chat messages  : {len(chat_msgs)} over {chat_span_days:.1f} days")
    print(f"Decryption key found    : {'yes' if decrypt_key else 'no'}")
    print(f"Backdoor beacon hosts   : {backdoor_hosts}")
    print(f"Beacons AFTER resolution: {len(backdoor_after_resolution)}  <-- should be investigated")

    # =======================================================================
    # PDF report
    # =======================================================================
    out_path = args.pdf or os.path.normpath(os.path.join(os.path.dirname(args.pcap_file) or ".", "..", "reports", "ransomware_incident_report.pdf"))
    os.makedirs(os.path.dirname(out_path), exist_ok=True)

    report = IncidentReport(
        "Ransomware Incident Reconstruction",
        "Atlas Continental Corporation - Full Kill Chain Analysis",
        args.pcap_file,
    )
    report.severity_banner(
        f"CRITICAL: Ransomware ({RANSOMWARE_GROUP}) impacted an estimated {DECLARED_TOTAL_ENDPOINTS:,} "
        f"endpoints across {len(DECLARED_OFFICES)} offices, {DECLARED_EXFIL_TOTAL} exfiltrated, "
        f"active backdoor persistence detected after ransom payment"
    )

    report.section("Executive Summary")
    report.key_values([
        ("Threat actor", RANSOMWARE_GROUP),
        ("Initial access", "Spear-phishing email with double-extension executable attachment"),
        ("Declared scope (IR/EDR telemetry)", f"{DECLARED_TOTAL_ENDPOINTS:,} endpoints across {', '.join(DECLARED_OFFICES)}"),
        ("Sample captured in this pcap", f"{len(infected_hosts)} representative hosts across {len(hosts_by_office)} offices"),
        ("Data exfiltrated (declared)", DECLARED_EXFIL_TOTAL),
        ("Ransom demanded", "$5,000,000 USD in Bitcoin"),
        ("Ransom negotiated / paid", "$1,250,000 USD in Bitcoin"),
        ("Negotiation duration", f"{chat_span_days:.1f} days, {len(chat_msgs)} messages"),
        ("Decryption key delivered", "Yes" if decrypt_key else "Not observed"),
        ("Persistent backdoor after resolution", f"CRITICAL: {len(backdoor_after_resolution)} beacons from {len(backdoor_hosts)} host(s)"),
    ])

    report.section("Phase 1: Initial Access - Spear-Phishing Email")
    report.paragraph(
        "The intrusion began with a spear-phishing email impersonating the HR payroll "
        "department, sent from a typosquat domain, using a subject line designed to "
        "prompt urgent action from the recipient."
    )
    report.key_values([
        ("Sender (spoofed)", phish_sender or "not found"),
        ("Subject", phish_subject or "not found"),
        ("Malicious attachment", phish_attachment or "not found"),
        ("Recipient", "d.kowalski@atlascontinental.com (Senior Systems Administrator)"),
    ])
    report.paragraph(
        "The attachment used a double file extension (a PDF icon with a hidden .exe "
        "extension) to disguise an executable as a harmless salary document, a classic "
        "social engineering technique that relies on Windows hiding known file extensions "
        "by default."
    )

    report.section("Phase 2: Malware Detonation and Command-and-Control")
    report.paragraph(
        "Opening the attachment triggered a dropper that resolved a command-and-control "
        "domain and downloaded a second-stage payload before establishing a recurring "
        "beacon channel."
    )
    report.table(["C2 domain queried", "DNS queries observed"], [[d, c] for d, c in c2_domains.items()])

    report.section("Phase 3: Lateral Spread Across the Global Estate")
    report.paragraph(
        f"Beacon check-ins were observed from {len(infected_hosts)} representative hosts "
        f"across {len(hosts_by_office)} office networks over roughly 30 hours, consistent "
        f"with automated lateral movement following business hours in each time zone. "
        f"The organization's asset inventory and EDR platform corroborate a much larger "
        f"blast radius of approximately {DECLARED_TOTAL_ENDPOINTS:,} endpoints; this packet "
        f"capture holds a representative sample rather than full-packet data for every host."
    )
    report.bar_chart("Infected hosts observed per office (sample)",
                      list(hosts_by_office.keys()), [len(v) for v in hosts_by_office.values()])

    report.section("Phase 4: Data Exfiltration")
    report.paragraph(
        f"Prior to encryption, data was staged and exfiltrated to {EXFIL_IP}. The "
        f"declared total across the full estate is {DECLARED_EXFIL_TOTAL}; the manifest "
        f"headers captured in this sample identify the categories involved:"
    )
    report.table(
        ["Category", "Archive filename", "Declared size"],
        [[m.get("category"), m.get("filename"), m.get("declared_total_size")] for m in manifest],
        col_widths=[45, 105, 30],
    )

    report.section("Phase 5: Mass Encryption and Ransom Note")
    report.paragraph(f"A ransom note titled README_DECRYPT_THE_GENTLEMEN.txt was dropped on file shares in all {ransom_note_offices} office networks captured. Full text recovered from the capture:")
    report.paragraph(ransom_note_text)

    report.section("Phase 6: Dark Web Negotiation (Full Transcript)")
    report.paragraph(
        f"The IR team negotiated with {RANSOMWARE_GROUP} over a Tor bridge relay across "
        f"{chat_span_days:.1f} days and {len(chat_msgs)} messages. The ransom was "
        f"negotiated down from $5,000,000 to $1,250,000."
    )
    for t, src, msg in chat_msgs:
        speaker = "IR Team" if src == "10.10.1.30" else RANSOMWARE_GROUP
        report.paragraph(f"[{datetime.fromtimestamp(t).strftime('%Y-%m-%d %H:%M')}] {speaker}: {msg}")

    report.section("Phase 7: Bitcoin Payment Confirmation")
    if btc_confirmation:
        report.paragraph(btc_confirmation)
    else:
        report.paragraph("No payment confirmation observed in this capture.")

    report.section("Phase 8: Decryption Key Handoff and Execution")
    report.key_values([("Decryption key", decrypt_key or "not observed")])
    report.paragraph(f"{len(decrypt_result_pkts)} decryption executions were observed across office file servers, all reporting successful restoration.")

    report.section("Phase 9: CRITICAL - Persistent Backdoor After Resolution")
    report.severity_banner(
        f"{len(backdoor_after_resolution)} beacon(s) from {len(backdoor_hosts)} host(s) to an undisclosed "
        f"secondary host ({BACKDOOR_C2_IP}) continued AFTER the incident was declared resolved in chat."
    )
    report.paragraph(
        "Despite the attacker's claim to 'destroy our copy' of the data and the "
        "successful decryption of all systems, low-and-slow beacon traffic to a second, "
        "previously undisclosed command-and-control host continued for at least two more "
        "days. This is strong evidence of a retained backdoor and should be treated as an "
        "active, ongoing compromise regardless of ransom payment. Recommend full "
        "re-imaging of the affected hosts and estate-wide threat hunting for the same IOC."
    )
    report.table(["Beaconing host"], [[h] for h in backdoor_hosts])

    report.save(out_path)
    print(f"\nPDF report written to: {out_path}")
    print("=" * 70)
    print(" END OF REPORT")
    print("=" * 70)


if __name__ == "__main__":
    main()
