import joblib

from backend.core.pcap_analyzer import analyze_pcap
from backend.core.ioc_detector import detect_iocs
from backend.core.ai_anomaly_detector import AnomalyDetector


MODEL_PATH = "models/threat_classifier.joblib"


def investigate_pcap(file_path: str) -> dict:
    """Run the complete forensic and AI investigation."""

    evidence = analyze_pcap(file_path)

    # Deterministic cybersecurity analysis
    findings = detect_iocs(evidence)

    # AI anomaly analysis
    ai_detector = AnomalyDetector()
    ai_detector.fit(evidence)
    anomalies = ai_detector.predict(evidence)

    # Load the pre-trained supervised threat classifier.
    trained_model = joblib.load(MODEL_PATH)

    features = __import__(
        "backend.core.feature_engineering",
        fromlist=["build_network_features"],
    ).build_network_features(evidence)

    predictions = trained_model.predict(features)
    probabilities = trained_model.predict_proba(features)[:, 1]

    classifications = []

    for event, prediction, probability in zip(
        evidence,
        predictions,
        probabilities,
    ):
        classifications.append({
            "event": event,
            "is_threat": bool(prediction == 1),
            "threat_probability": round(
                float(probability),
                4,
            ),
        })

    return {
        "evidence": evidence,
        "findings": findings,
        "ai_analysis": anomalies,
        "threat_classification": classifications,
        "summary": {
            "packets_analyzed": len(evidence),
            "findings_detected": len(findings),
            "ai_anomalies_detected": int(
                sum(
                    result["is_anomaly"]
                    for result in anomalies
                )
            ),
            "threats_classified": int(
                sum(
                    result["is_threat"]
                    for result in classifications
                )
            ),
            "maximum_risk_score": max(
                (
                    finding["risk_score"]
                    for finding in findings
                ),
                default=0,
            ),
        },
    }