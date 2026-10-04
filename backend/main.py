import argparse

from backend.core.pcap_analyzer import analyze_pcap
from backend.utils.evidence_writer import save_evidence


def main():
    parser = argparse.ArgumentParser(
        description="TraceX - Digital Forensics Platform"
    )

    parser.add_argument(
        "pcap",
        help="Path to the PCAP file"
    )

    parser.add_argument(
        "-o",
        "--output",
        default="evidence.json",
        help="Output JSON file"
    )

    args = parser.parse_args()

    print("[TraceX] Loading PCAP...")
    evidence = analyze_pcap(args.pcap)

    print(f"[TraceX] Packets analyzed: {len(evidence)}")

    save_evidence(evidence, args.output)

    print(f"[TraceX] Evidence saved to: {args.output}")


if __name__ == "__main__":
    main()