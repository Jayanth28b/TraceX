from scapy.all import IP, TCP, wrpcap


OUTPUT_PATH = "samples/malicious_rdp.pcap"


def create_rdp_test_pcap():
    """
    Create a controlled synthetic PCAP containing
    RDP connection attempts.

    This is test data for validating TraceX detection.
    """

    packets = []

    source_ip = "192.168.1.10"
    destination_ip = "192.168.1.20"

    source_port = 49152
    destination_port = 3389

    # RDP connection attempt
    syn = (
        IP(
            src=source_ip,
            dst=destination_ip,
        )
        / TCP(
            sport=source_port,
            dport=destination_port,
            flags="S",
            seq=1000,
        )
    )

    # RDP server response
    syn_ack = (
        IP(
            src=destination_ip,
            dst=source_ip,
        )
        / TCP(
            sport=destination_port,
            dport=source_port,
            flags="SA",
            seq=2000,
            ack=1001,
        )
    )

    # Client ACK
    ack = (
        IP(
            src=source_ip,
            dst=destination_ip,
        )
        / TCP(
            sport=source_port,
            dport=destination_port,
            flags="A",
            seq=1001,
            ack=2001,
        )
    )

    packets.extend([
        syn,
        syn_ack,
        ack,
    ])

    wrpcap(
        OUTPUT_PATH,
        packets,
    )

    print(
        f"[TraceX] Malicious RDP test PCAP created: "
        f"{OUTPUT_PATH}"
    )


if __name__ == "__main__":
    create_rdp_test_pcap()