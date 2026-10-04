from backend.core.pcap_analyzer import analyze_pcap
from backend.core.ioc_detector import detect_iocs
from backend.core.ai_anomaly_detector import AnomalyDetector


def investigate_pcap(file_path: str) -> dict:
    """Run the complete forensic and AI investigation."""

    evidence = analyze_pcap(file_path)

    # Deterministic cybersecurity analysis
    findings = detect_iocs(evidence)

    # AI anomaly analysis
    ai_detector = AnomalyDetector()
    ai_detector.fit(evidence)
    anomalies = ai_detector.predict(evidence)

    return {
        "evidence": evidence,
        "findings": findings,
        "ai_analysis": anomalies,
        "summary": {
            "packets_analyzed": len(evidence),
            "findings_detected": len(findings),
            "ai_anomalies_detected": sum(
                result["is_anomaly"] for result in anomalies
            ),
            "maximum_risk_score": max(
                (finding["risk_score"] for finding in findings),
                default=0,
            ),
        },
    }