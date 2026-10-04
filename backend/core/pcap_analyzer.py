from backend.parsers.pcap_parser import load_pcap
from backend.core.evidence_extractor import extract_packet_evidence


def analyze_pcap(file_path: str):
    """Analyze every packet in a PCAP and return structured evidence."""

    packets = load_pcap(file_path)

    return [
        extract_packet_evidence(packet)
        for packet in packets
    ]