from ipaddress import ip_address


SUSPICIOUS_PORTS = {
    21: "FTP",
    23: "Telnet",
    445: "SMB",
    3389: "RDP",
    4444: "Common Metasploit",
}


def is_public_ip(value: str) -> bool:
    """Return True if the IP address is publicly routable."""

    try:
        return ip_address(value).is_global
    except ValueError:
        return False


def detect_iocs(evidence: list[dict]) -> list[dict]:
    """
    Detect suspicious network indicators.

    Public IP addresses and DNS queries are treated as
    network observations, not malicious indicators by themselves.
    """

    findings = []

    for event in evidence:
        destination_ip = event.get("destination_ip")
        destination_port = event.get("destination_port")

        risk_score = 0
        reasons = []

        if destination_port in SUSPICIOUS_PORTS:
            risk_score += 50
            reasons.append(
                f"Port associated with {SUSPICIOUS_PORTS[destination_port]}"
            )

        if risk_score > 0:
            risk_score = min(risk_score, 100)

            findings.append({
                "type": "NETWORK_INDICATOR",
                "value": destination_ip,
                "reason": "; ".join(reasons),
                "risk_score": risk_score,
            })

    return findings