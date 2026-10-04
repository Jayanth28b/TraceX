from scapy.all import IP, TCP, UDP, DNS, DNSQR, Ether, wrpcap


packets = [
    Ether() / IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=50000, dport=53) /
    DNS(rd=1, qd=DNSQR(qname="example.com")),

    Ether() / IP(src="192.168.1.10", dst="192.168.1.20") /
    TCP(sport=50001, dport=80, flags="S"),

    Ether() / IP(src="192.168.1.20", dst="192.168.1.10") /
    TCP(sport=80, dport=50001, flags="SA"),
]

wrpcap("samples/test_capture.pcap", packets)

print("Sample PCAP created: samples/test_capture.pcap")