from scapy.all import rdpcap, sniff, DNS, DNSQR, IP, TCP
from collections import defaultdict
import math


# CONFIGURATION

MODE = "demo"        # "pcap", "live", or "demo"
PCAP_FILE = "sample_dns.pcap"

# ENTROPY

def calculate_entropy(data):
    if not data:
        return 0
    freq = {}
    for c in data:
        freq[c] = freq.get(c, 0) + 1
    ent = 0
    for count in freq.values():
        p = count / len(data)
        ent -= p * math.log2(p)
    return ent

# ALERT STORE (DEDUPLICATED)

alerts = []
reported = set()

def raise_alert(alert_type, src, reason, severity, mode="Detected"):
    key = (alert_type, src, reason)
    if key not in reported:
        reported.add(key)
        alerts.append({
            "Type": alert_type,
            "Source IP": src,
            "Reason": reason,
            "Severity": severity,
            "Mode": mode
        })

# DETECTION MODULES

beacon_tracker = defaultdict(list)
port_usage = defaultdict(int)
COMMON_PORTS = {80, 443, 53}

def detect_dns_tunneling(pkt, mode="Detected"):
    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR) and pkt.haslayer(IP):
        query = pkt[DNSQR].qname.decode(errors="ignore")
        src = pkt[IP].src
        length = len(query)
        entropy = calculate_entropy(query)

        if length > 50 and entropy > 4.0:
            raise_alert(
                "DNS Tunneling",
                src,
                f"High-entropy DNS query (len={length}, entropy={round(entropy,2)})",
                "High",
                mode
            )

def detect_beaconing(pkt, mode="Detected"):
    if pkt.haslayer(IP):
        src = pkt[IP].src
        dst = pkt[IP].dst
        ts = float(pkt.time)

        beacon_tracker[(src, dst)].append(ts)
        times = beacon_tracker[(src, dst)]

        if len(times) >= 5:
            gaps = [times[i+1] - times[i] for i in range(len(times)-1)]
            if max(gaps) - min(gaps) < 2:
                raise_alert(
                    "Malware Beaconing",
                    src,
                    f"Periodic communication to {dst}",
                    "High",
                    mode
                )

def detect_unusual_ports(pkt, mode="Detected"):
    if pkt.haslayer(TCP) and pkt.haslayer(IP):
        src = pkt[IP].src
        port = pkt[TCP].dport
        port_usage[(src, port)] += 1

        if port not in COMMON_PORTS and port_usage[(src, port)] > 15:
            raise_alert(
                "Unusual Port Usage",
                src,
                f"High traffic on non-standard port {port}",
                "Medium",
                mode
            )

def detect_protocol_violation(pkt, mode="Detected"):
    if pkt.haslayer(TCP) and pkt.haslayer(IP):
        if pkt[TCP].flags == 0:
            raise_alert(
                "Protocol Violation",
                pkt[IP].src,
                "TCP packet with invalid flag combination",
                "Low",
                mode
            )

# PACKET PROCESSOR

def process_packet(pkt, mode="Detected"):
    detect_dns_tunneling(pkt, mode)
    detect_beaconing(pkt, mode)
    detect_unusual_ports(pkt, mode)
    detect_protocol_violation(pkt, mode)

# RUN MODES

def run_pcap():
    packets = rdpcap(PCAP_FILE)
    for pkt in packets:
        process_packet(pkt, "Detected")

def run_live():
    print("[INFO] Live capture started (DNS traffic)...")
    sniff(filter="dns", prn=lambda p: process_packet(p, "Detected"), store=False)

def run_demo():
    print("[INFO] Demo mode: injecting simulated attacks")

    # Simulated DNS tunneling
    class FakeDNS:
        pass

    pkt = IP(src="192.168.100.50", dst="8.8.8.8") / \
          DNS(rd=1, qd=DNSQR(qname="aGVsbG93b3JsZGFiY2RlZmdoaWprbW5vcHFyc3R1dnd4eXo.example.com"))
    process_packet(pkt, "Simulated")

    # Simulated unusual port
    for _ in range(20):
        pkt = IP(src="10.0.0.5", dst="10.0.0.1") / TCP(dport=4444, flags="S")
        process_packet(pkt, "Simulated")

    # Simulated protocol violation
    pkt = IP(src="172.16.0.9", dst="172.16.0.1") / TCP(flags=0)
    process_packet(pkt, "Simulated")

# MAIN

if __name__ == "__main__":
    if MODE == "pcap":
        run_pcap()
    elif MODE == "live":
        run_live()
    elif MODE == "demo":
        run_demo()

    if alerts:
        print("\n[ALERTS DETECTED]\n")
        for alert in alerts:
            print(alert)
    else:
        print("\n[INFO] No suspicious activity detected.\n")
import json

with open("alerts.json", "w") as f:
    json.dump(alerts, f, indent=4)

import subprocess
import sys
import time
import webbrowser

def launch_dashboard():
    print("\n[INFO] Launching dashboard...")
    subprocess.Popen(
        ["streamlit", "run", "dashboard.py"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    time.sleep(3)
    webbrowser.open("http://localhost:8501")


if __name__ == "__main__":

    launch_dashboard()

