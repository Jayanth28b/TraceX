from scapy.all import IP, TCP, wrpcap


OUTPUT_PATH = "samples/c2_like.pcap"


def create_c2_like_pcap():
    """
    Create a controlled synthetic PCAP containing repeated,
    regularly timed communication between two hosts.

    This is test data for validating TraceX behavioral
    command-and-control detection.
    """

    source_ip = "192.168.1.10"
    destination_ip = "192.168.1.50"

    source_port = 50000
    destination_port = 443

    packets = []

    timestamps = [
        1000.0,
        1010.0,
        1020.0,
        1030.0,
    ]

    for index, timestamp in enumerate(timestamps):

        packet = (
            IP(
                src=source_ip,
                dst=destination_ip,
            )
            / TCP(
                sport=source_port + index,
                dport=destination_port,
                flags="S",
                seq=1000 + index,
            )
        )

        packet.time = timestamp
        packets.append(packet)

    wrpcap(
        OUTPUT_PATH,
        packets,
    )

    print(
        "[TraceX] C2-like behavioral test PCAP created: "
        f"{OUTPUT_PATH}"
    )


if __name__ == "__main__":
    create_c2_like_pcap()