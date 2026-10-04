def correlate_event(
    event: dict,
    event_risk: dict,
    attack_stages: list[dict],
    mitre_techniques: list[dict],
) -> dict:
    """
    Correlate deterministic, AI, behavioral, and MITRE signals
    for a single network event.

    The result is an investigative finding, not proof of compromise.
    """

    risk_score = event_risk.get("risk_score", 0)
    ioc_risk = event_risk.get("ioc_risk", 0)
    is_anomaly = event_risk.get("is_anomaly", False)
    anomaly_score = event_risk.get("anomaly_score", 0)
    is_threat = event_risk.get("is_threat", False)
    threat_probability = event_risk.get(
        "threat_probability",
        0,
    )

    matched_stages = []

    for result in attack_stages:
        if result.get("event") == event:
            matched_stages.extend(
                result.get("stages", [])
            )

    matched_techniques = []

    for result in mitre_techniques:
        if result.get("event") == event:
            matched_techniques.extend(
                result.get("techniques", [])
            )

    signals = []

    if ioc_risk > 0:
        signals.append("IOC")

    if is_anomaly:
        signals.append("AI_ANOMALY")

    if is_threat:
        signals.append("AI_THREAT")

    if matched_stages:
        signals.append("ATTACK_STAGE")

    if matched_techniques:
        signals.append("MITRE_MAPPING")

    # Build an investigator-oriented assessment.
    assessment_parts = []

    if ioc_risk > 0:
        assessment_parts.append(
            "A suspicious network indicator was detected."
        )

    if is_threat:
        assessment_parts.append(
            "The AI threat classifier identified potentially "
            "malicious behavior."
        )

    if is_anomaly:
        assessment_parts.append(
            "The AI anomaly detector identified unusual "
            "network behavior."
        )

    if matched_stages:
        stage_names = [
            stage.get("stage")
            for stage in matched_stages
        ]

        assessment_parts.append(
            "Potential attack stage(s): "
            + ", ".join(stage_names)
            + "."
        )

    if matched_techniques:
        assessment_parts.append(
            "The observed behavior has a potential "
            "MITRE ATT&CK mapping."
        )

    if risk_score >= 75:
        priority = (
            "High-priority activity requiring immediate "
            "investigation."
        )
    elif risk_score >= 50:
        priority = (
            "Suspicious activity requiring further "
            "investigation."
        )
    elif risk_score >= 25:
        priority = (
            "Potentially suspicious activity that should "
            "be reviewed in context."
        )
    elif assessment_parts:
        priority = (
            "Low-risk activity with one or more investigative "
            "signals."
        )
    else:
        priority = "Low-risk network activity."

    if assessment_parts:
        assessment = priority + " " + " ".join(
            assessment_parts
        )
    else:
        assessment = priority

    return {
        "event": event,
        "risk_score": risk_score,
        "signals": signals,
        "ioc_risk": ioc_risk,
        "ai_anomaly": {
            "detected": is_anomaly,
            "score": anomaly_score,
        },
        "ai_threat": {
            "detected": is_threat,
            "probability": threat_probability,
        },
        "attack_stages": matched_stages,
        "mitre_techniques": matched_techniques,
        "assessment": assessment,
    }