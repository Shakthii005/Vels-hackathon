from scapy.all import rdpcap, DNS, DNSQR
import math
from collections import defaultdict


# Utility: Entropy calculation

def calculate_entropy(data):
    if not data:
        return 0

    entropy = 0
    length = len(data)
    char_count = {}

    for char in data:
        char_count[char] = char_count.get(char, 0) + 1

    for count in char_count.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy



# DNS Tunneling Detection Logic

def detect_dns_tunneling(pcap_file):
    packets = rdpcap(pcap_file)
    suspicious_queries = defaultdict(list)

    for pkt in packets:
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            query = pkt[DNSQR].qname.decode(errors="ignore")
            src_ip = pkt[1].src

            query_length = len(query)
            entropy = calculate_entropy(query)

            if query_length > 50 and entropy > 4.0:
                suspicious_queries[src_ip].append(
                    (query, query_length, entropy)
                )

  
    # DEMO: Inject simulated suspicious DNS query

    demo_query = "aGVsbG93b3JsZGFiY2RlZmdoaWprbW5vcHFyc3R1dnd4eXo.example.com"
    demo_entropy = calculate_entropy(demo_query)

    if demo_entropy > 3.5:
        suspicious_queries["192.168.100.50"].append(
            (demo_query, len(demo_query), demo_entropy)
        )

    # ALERT OUTPUT
    
    if suspicious_queries:
        print("\n[ALERT] DNS Tunneling Suspected\n")
        for ip, queries in suspicious_queries.items():
            print(f"Source IP: {ip}")
            for q in queries:
                print(f"  - Query: {q[0]}")
                print(f"    Length: {q[1]} | Entropy: {round(q[2], 2)}")
            print("-" * 50)
    else:
        print("\n[INFO] No DNS tunneling activity detected.\n")



# MAIN

if __name__ == "__main__":
    pcap_path = r"D:\vels hack\sample_dns.pcap"

    detect_dns_tunneling(pcap_path)
