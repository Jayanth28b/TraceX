import argparse
from pathlib import Path

from backend.core.investigation import investigate_pcap
from backend.utils.html_report import generate_html_report
from backend.utils.report_writer import save_investigation_report


def main():
    parser = argparse.ArgumentParser(
        description="TraceX - AI-Assisted Digital Forensics Platform"
    )

    parser.add_argument(
        "pcap",
        help="Path to the PCAP file",
    )

    parser.add_argument(
        "-o",
        "--output",
        default="samples/investigation_report.json",
        help="Output JSON investigation report",
    )

    parser.add_argument(
        "--html",
        default="samples/investigation_report.html",
        help="Output HTML investigation report",
    )

    args = parser.parse_args()

    print("=" * 60)
    print("TraceX - Digital Forensics Investigation")
    print("=" * 60)

    print("\n[TraceX] Starting investigation...")
    report = investigate_pcap(args.pcap)

    summary = report["summary"]

    print(f"[TraceX] Packets analyzed: {summary['packets_analyzed']}")
    print(f"[TraceX] IOC findings: {summary['findings_detected']}")
    print(f"[TraceX] AI anomalies: {summary['ai_anomalies_detected']}")
    print(f"[TraceX] Threats classified: {summary['threats_classified']}")
    print(f"[TraceX] Timeline events: {summary['timeline_events']}")
    print(
        "[TraceX] MITRE techniques: "
        f"{summary['mitre_techniques_observed']}"
    )
    print(
        "[TraceX] Maximum risk score: "
        f"{summary['maximum_risk_score']}/100"
    )
    print(
        "[TraceX] Severity: "
        f"{summary['severity']}"
    )

    save_investigation_report(
        report,
        args.output,
    )

    generate_html_report(
        report,
        args.html,
    )

    print(f"\n[TraceX] JSON report: {Path(args.output)}")
    print(f"[TraceX] HTML report: {Path(args.html)}")
    print("\n[TraceX] Investigation completed.")


if __name__ == "__main__":
    main()