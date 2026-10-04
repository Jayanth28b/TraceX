from scapy.all import IP, TCP, wrpcap


OUTPUT_PATH = "samples/reconnaissance.pcap"


def create_reconnaissance_pcap():
    """
    Create a controlled synthetic PCAP containing
    multi-port scanning behavior.

    This is test data for validating TraceX reconnaissance
    detection.
    """

    source_ip = "192.168.1.10"
    destination_ip = "192.168.1.20"

    destination_ports = [
        21,
        22,
        80,
    ]

    packets = []

    for index, destination_port in enumerate(
        destination_ports
    ):
        packet = (
            IP(
                src=source_ip,
                dst=destination_ip,
            )
            / TCP(
                sport=50000 + index,
                dport=destination_port,
                flags="S",
                seq=1000 + index,
            )
        )

        packets.append(packet)

    wrpcap(
        OUTPUT_PATH,
        packets,
    )

    print(
        "[TraceX] Reconnaissance test PCAP created: "
        f"{OUTPUT_PATH}"
    )


if __name__ == "__main__":
    create_reconnaissance_pcap()