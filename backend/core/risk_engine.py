def calculate_event_risk(
    ioc_risk: float,
    threat_probability: float,
    is_anomaly: bool,
) -> float:
    """
    Combine deterministic and AI signals into a 0-100 event risk score.
    """

    ioc_component = max(0.0, min(ioc_risk, 100.0))
    threat_component = max(
        0.0,
        min(threat_probability, 1.0),
    ) * 100.0
    anomaly_component = 100.0 if is_anomaly else 0.0

    risk = (
        0.50 * ioc_component
        + 0.30 * threat_component
        + 0.20 * anomaly_component
    )

    return round(min(risk, 100.0), 2)