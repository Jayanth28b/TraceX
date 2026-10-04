from ipaddress import ip_address


SUSPICIOUS_PORTS = {
    21,
    23,
    445,
    3389,
    4444,
}


def is_public_ip(value: str) -> bool:
    """Return True if the IP address is publicly routable."""

    try:
        return ip_address(value).is_global
    except ValueError:
        return False


def build_network_features(evidence: list[dict]) -> list[list[float]]:
    """
    Convert network evidence into behavior-oriented ML features.

    Features:
    1. Log-scaled packet size
    2. DNS indicator
    3. HTTP indicator
    4. HTTPS indicator
    5. Suspicious-port indicator
    6. Public-destination indicator
    7. TCP indicator
    8. UDP indicator
    """

    features = []

    for event in evidence:
        packet_length = max(event.get("packet_length", 0), 1)
        destination_port = event.get("destination_port") or 0
        protocol = event.get("protocol")

        features.append([
            __import__("math").log1p(packet_length),
            1 if event.get("dns_query") else 0,
            1 if destination_port == 80 else 0,
            1 if destination_port == 443 else 0,
            1 if destination_port in SUSPICIOUS_PORTS else 0,
            1 if is_public_ip(event.get("destination_ip", "")) else 0,
            1 if protocol == "TCP" else 0,
            1 if protocol == "UDP" else 0,
        ])

    return features