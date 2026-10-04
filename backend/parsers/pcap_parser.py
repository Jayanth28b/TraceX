from scapy.all import rdpcap


def load_pcap(file_path: str):
    """
    Load packets from a PCAP file.
    """
    return rdpcap(file_path)