import joblib

from backend.core.pcap_analyzer import analyze_pcap
from backend.core.ioc_detector import detect_iocs
from backend.core.ai_anomaly_detector import AnomalyDetector
from backend.core.feature_engineering import build_network_features
from backend.core.risk_engine import calculate_event_risk
from backend.core.timeline import build_timeline
from backend.core.mitre_mapper import map_evidence_to_mitre
from backend.core.severity import calculate_severity


MODEL_PATH = "models/threat_classifier.joblib"


def investigate_pcap(file_path: str) -> dict:
    """Run the complete forensic and AI investigation."""

    # ---------------------------------------------------------
    # 1. Extract network evidence from the PCAP
    # ---------------------------------------------------------
    evidence = analyze_pcap(file_path)

    # ---------------------------------------------------------
    # 2. Deterministic cybersecurity analysis
    # ---------------------------------------------------------
    findings = detect_iocs(evidence)

    # ---------------------------------------------------------
    # 3. AI anomaly analysis
    # ---------------------------------------------------------
    ai_detector = AnomalyDetector()
    ai_detector.fit(evidence)
    anomalies = ai_detector.predict(evidence)

    # ---------------------------------------------------------
    # 4. Load the pre-trained supervised threat classifier
    # ---------------------------------------------------------
    trained_model = joblib.load(MODEL_PATH)

    features = build_network_features(evidence)

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

    # ---------------------------------------------------------
    # 5. Calculate event-level risk scores
    # ---------------------------------------------------------
    event_risk = []

    for index, event in enumerate(evidence):
        destination_ip = event.get("destination_ip")

        matching_findings = [
            finding
            for finding in findings
            if finding["value"] == destination_ip
        ]

        ioc_risk = max(
            (
                finding["risk_score"]
                for finding in matching_findings
            ),
            default=0,
        )

        anomaly_result = anomalies[index]
        classification_result = classifications[index]

        risk_score = calculate_event_risk(
            ioc_risk=ioc_risk,
            threat_probability=classification_result[
                "threat_probability"
            ],
            is_anomaly=anomaly_result["is_anomaly"],
        )

        event_risk.append({
            "event": event,
            "risk_score": risk_score,
            "ioc_risk": ioc_risk,
            "is_anomaly": anomaly_result["is_anomaly"],
            "anomaly_score": anomaly_result["anomaly_score"],
            "is_threat": classification_result["is_threat"],
            "threat_probability": classification_result[
                "threat_probability"
            ],
        })

    # ---------------------------------------------------------
    # 6. Calculate overall risk score
    # ---------------------------------------------------------
    maximum_event_risk = max(
        (
            result["risk_score"]
            for result in event_risk
        ),
        default=0,
    )

    # ---------------------------------------------------------
    # 7. Convert risk score into severity
    # ---------------------------------------------------------
    overall_severity = calculate_severity(
        maximum_event_risk
    )

    # ---------------------------------------------------------
    # 8. Reconstruct chronological forensic timeline
    # ---------------------------------------------------------
    timeline = build_timeline(evidence)

    # ---------------------------------------------------------
    # 9. Map observable behavior to potential MITRE ATT&CK
    # ---------------------------------------------------------
    mitre_attack = map_evidence_to_mitre(evidence)

    # ---------------------------------------------------------
    # 10. Return complete investigation report
    # ---------------------------------------------------------
    return {
        "evidence": evidence,
        "findings": findings,
        "ai_analysis": anomalies,
        "threat_classification": classifications,
        "event_risk": event_risk,
        "timeline": timeline,
        "mitre_attack": mitre_attack,

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

            "timeline_events": len(timeline),

            "mitre_techniques_observed": len(
                {
                    technique["technique_id"]
                    for result in mitre_attack
                    for technique in result["techniques"]
                }
            ),

            "maximum_risk_score": maximum_event_risk,

            "severity": overall_severity,
        },
    }