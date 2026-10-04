def calculate_severity(risk_score: float) -> str:
    """Convert a 0-100 risk score into a severity level."""

    if risk_score >= 75:
        return "CRITICAL"

    if risk_score >= 50:
        return "HIGH"

    if risk_score >= 25:
        return "MEDIUM"

    return "LOW"