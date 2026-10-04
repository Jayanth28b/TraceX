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

    # ---------------------------------------------------------
    # Validate input PCAP
    # ---------------------------------------------------------

    pcap_path = Path(args.pcap)

    if not pcap_path.exists():
        print(
            f"\n[TraceX] ERROR: PCAP file not found:"
            f" {pcap_path}"
        )
        return 1

    if not pcap_path.is_file():
        print(
            f"\n[TraceX] ERROR: Input path is not a file:"
            f" {pcap_path}"
        )
        return 1

    if pcap_path.suffix.lower() not in {
        ".pcap",
        ".pcapng",
    }:
        print(
            "\n[TraceX] ERROR: Unsupported file format."
        )
        print(
            "[TraceX] Please provide a .pcap or .pcapng file."
        )
        return 1

    print(
        f"\n[TraceX] Input PCAP: {pcap_path}"
    )

    # ---------------------------------------------------------
    # Investigation
    # ---------------------------------------------------------

    print("[TraceX] Starting investigation...")

    try:
        report = investigate_pcap(
            str(pcap_path)
        )

    except FileNotFoundError:
        print(
            "\n[TraceX] ERROR: Required model or input file "
            "could not be found."
        )
        return 1

    except PermissionError:
        print(
            "\n[TraceX] ERROR: Permission denied while "
            "accessing the investigation files."
        )
        return 1

    except Exception as error:
        print(
            "\n[TraceX] ERROR: Investigation failed."
        )
        print(
            f"[TraceX] Details: {error}"
        )
        return 1

    # ---------------------------------------------------------
    # Display investigation summary
    # ---------------------------------------------------------

    summary = report["summary"]

    print(
        f"[TraceX] Packets analyzed: "
        f"{summary['packets_analyzed']}"
    )

    print(
        f"[TraceX] IOC findings: "
        f"{summary['findings_detected']}"
    )

    print(
        f"[TraceX] AI anomalies: "
        f"{summary['ai_anomalies_detected']}"
    )

    print(
        f"[TraceX] Threats classified: "
        f"{summary['threats_classified']}"
    )

    print(
        f"[TraceX] Timeline events: "
        f"{summary['timeline_events']}"
    )

    print(
        "[TraceX] MITRE techniques: "
        f"{summary['mitre_techniques_observed']}"
    )

    print(
        "[TraceX] Attack stage events: "
        f"{summary.get('attack_stage_events', 0)}"
    )

    print(
        "[TraceX] Behavioral attack patterns: "
        f"{summary.get('behavioral_attack_patterns', 0)}"
    )

    print(
        "[TraceX] Correlated findings: "
        f"{summary.get('correlated_findings', 0)}"
    )

    print(
        "[TraceX] Maximum risk score: "
        f"{summary['maximum_risk_score']}/100"
    )

    print(
        "[TraceX] Severity: "
        f"{summary['severity']}"
    )

    # ---------------------------------------------------------
    # Save reports
    # ---------------------------------------------------------

    try:
        save_investigation_report(
            report,
            args.output,
        )

        generate_html_report(
            report,
            args.html,
        )

    except PermissionError:
        print(
            "\n[TraceX] ERROR: Permission denied while "
            "writing the investigation report."
        )
        return 1

    except OSError as error:
        print(
            "\n[TraceX] ERROR: Could not write the reports."
        )
        print(
            f"[TraceX] Details: {error}"
        )
        return 1

    print(
        f"\n[TraceX] JSON report: "
        f"{Path(args.output)}"
    )

    print(
        f"[TraceX] HTML report: "
        f"{Path(args.html)}"
    )

    print(
        "\n[TraceX] Investigation completed."
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())