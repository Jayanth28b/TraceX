MITRE_MAPPINGS = {
    "DNS": {
        "technique_id": "T1071.004",
        "technique_name": "DNS",
        "description": "DNS traffic observed in network evidence.",
    },
    "HTTP": {
        "technique_id": "T1071.001",
        "technique_name": "Web Protocols",
        "description": "HTTP traffic observed in network evidence.",
    },
    "HTTPS": {
        "technique_id": "T1071.001",
        "technique_name": "Web Protocols",
        "description": "HTTPS traffic observed in network evidence.",
    },
    "RDP": {
        "technique_id": "T1021.001",
        "technique_name": "Remote Services: RDP",
        "description": "RDP traffic observed on destination port 3389.",
    },
    "SMB": {
        "technique_id": "T1021.002",
        "technique_name": "Remote Services: SMB/Windows Admin Shares",
        "description": "SMB traffic observed on destination port 445.",
    },
}


def map_event_to_mitre(event: dict) -> list[dict]:
    """Map observable network behavior to potential MITRE ATT&CK techniques."""

    mappings = []

    destination_port = event.get("destination_port")

    if event.get("dns_query"):
        mappings.append(MITRE_MAPPINGS["DNS"])

    if destination_port == 80:
        mappings.append(MITRE_MAPPINGS["HTTP"])

    if destination_port == 443:
        mappings.append(MITRE_MAPPINGS["HTTPS"])

    if destination_port == 3389:
        mappings.append(MITRE_MAPPINGS["RDP"])

    if destination_port == 445:
        mappings.append(MITRE_MAPPINGS["SMB"])

    return [
        {
            "technique_id": mapping["technique_id"],
            "technique_name": mapping["technique_name"],
            "description": mapping["description"],
        }
        for mapping in mappings
    ]


def map_evidence_to_mitre(evidence: list[dict]) -> list[dict]:
    """Map all network evidence to potential MITRE ATT&CK techniques."""

    results = []

    for event in evidence:
        mappings = map_event_to_mitre(event)

        if mappings:
            results.append({
                "event": event,
                "techniques": mappings,
            })

    return results