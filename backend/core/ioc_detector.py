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
    """Analyze evidence and assign a 0-100 risk score."""

    findings = []

    for event in evidence:
        destination_ip = event.get("destination_ip")
        destination_port = event.get("destination_port")
        dns_query = event.get("dns_query")

        risk_score = 0
        reasons = []

        if destination_ip and is_public_ip(destination_ip):
            risk_score += 10
            reasons.append("Connection to a public IP address")

        if destination_port in SUSPICIOUS_PORTS:
            risk_score += 50
            reasons.append(
                f"Port associated with {SUSPICIOUS_PORTS[destination_port]}"
            )

        if dns_query:
            risk_score += 10
            reasons.append("DNS query observed")

        if risk_score > 0:
            risk_score = min(risk_score, 100)

            findings.append({
                "type": "NETWORK_INDICATOR",
                "value": destination_ip or dns_query,
                "reason": "; ".join(reasons),
                "risk_score": risk_score,
            })

    return findings