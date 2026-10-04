from scapy.all import Ether, IP, UDP, DNS, DNSQR

from backend.core.evidence_extractor import extract_packet_evidence


def test_extract_dns_evidence():
    packet = (
        Ether()
        / IP(src="192.168.1.10", dst="8.8.8.8")
        / UDP(sport=50000, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="example.com"))
    )

    evidence = extract_packet_evidence(packet)

    assert evidence["source_ip"] == "192.168.1.10"
    assert evidence["destination_ip"] == "8.8.8.8"
    assert evidence["protocol"] == "UDP"
    assert evidence["destination_port"] == 53
    assert evidence["dns_query"] == "example.com"