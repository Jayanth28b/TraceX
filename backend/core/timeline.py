from datetime import datetime, timezone


def build_timeline(evidence: list[dict]) -> list[dict]:
    """
    Build a chronological forensic timeline from network evidence.
    """

    sorted_evidence = sorted(
        evidence,
        key=lambda event: event.get("timestamp", 0),
    )

    timeline = []

    for index, event in enumerate(sorted_evidence, start=1):
        timestamp = event.get("timestamp")

        timeline.append({
            "sequence": index,
            "timestamp": timestamp,
            "datetime": (
                datetime.fromtimestamp(
                    timestamp,
                    tz=timezone.utc,
                ).isoformat()
                if timestamp is not None
                else None
            ),
            "source_ip": event.get("source_ip"),
            "destination_ip": event.get("destination_ip"),
            "protocol": event.get("protocol"),
            "source_port": event.get("source_port"),
            "destination_port": event.get("destination_port"),
            "dns_query": event.get("dns_query"),
            "packet_length": event.get("packet_length"),
        })

    return timeline