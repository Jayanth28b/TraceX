from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR


def extract_packet_evidence(packet):
    """Extract useful forensic metadata from a network packet."""

    evidence = {
        "timestamp": float(packet.time),
        "source_ip": None,
        "destination_ip": None,
        "protocol": None,
        "source_port": None,
        "destination_port": None,
        "dns_query": None,
        "packet_length": len(packet),
    }

    if IP in packet:
        evidence["source_ip"] = packet[IP].src
        evidence["destination_ip"] = packet[IP].dst

    if TCP in packet:
        evidence["protocol"] = "TCP"
        evidence["source_port"] = packet[TCP].sport
        evidence["destination_port"] = packet[TCP].dport

    elif UDP in packet:
        evidence["protocol"] = "UDP"
        evidence["source_port"] = packet[UDP].sport
        evidence["destination_port"] = packet[UDP].dport

    if DNS in packet and DNSQR in packet:
        evidence["dns_query"] = packet[DNSQR].qname.decode(
            errors="replace"
        ).rstrip(".")

    return evidence