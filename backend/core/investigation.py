from backend.core.pcap_analyzer import analyze_pcap
from backend.core.ioc_detector import detect_iocs


def investigate_pcap(file_path: str) -> dict:
    """Run the complete deterministic forensic investigation."""

    evidence = analyze_pcap(file_path)
    findings = detect_iocs(evidence)

    return {
        "evidence": evidence,
        "findings": findings,
        "summary": {
            "packets_analyzed": len(evidence),
            "findings_detected": len(findings),
            "maximum_risk_score": max(
                (finding["risk_score"] for finding in findings),
                default=0,
            ),
        },
    }