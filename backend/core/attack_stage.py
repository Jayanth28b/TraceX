ATTACK_STAGE_MAPPINGS = {
    "RECONNAISSANCE": {
        "description": (
            "Network behavior that may indicate reconnaissance "
            "or service discovery."
        )
    },
    "INITIAL_ACCESS": {
        "description": (
            "Network behavior that may indicate an attempt "
            "to gain initial access."
        )
    },
    "LATERAL_MOVEMENT": {
        "description": (
            "Network behavior associated with remote access "
            "or movement between systems."
        )
    },
    "COMMAND_AND_CONTROL": {
        "description": (
            "Repeated network communication that may indicate "
            "command-and-control behavior."
        )
    },
}


SUSPICIOUS_ACCESS_PORTS = {
    21,
    23,
    4444,
}


REMOTE_ACCESS_PORTS = {
    445,
    3389,
}


def detect_attack_stages(event: dict) -> list[dict]:
    """
    Identify potential attack stages from a single network event.

    These mappings represent investigative hypotheses based on
    observable network behavior. They do not prove that an
    attack occurred.
    """

    stages = []

    destination_port = event.get("destination_port")

    # ---------------------------------------------------------
    # Initial Access
    # ---------------------------------------------------------
    if destination_port in SUSPICIOUS_ACCESS_PORTS:
        stages.append({
            "stage": "INITIAL_ACCESS",
            "description": ATTACK_STAGE_MAPPINGS[
                "INITIAL_ACCESS"
            ]["description"],
        })

    # ---------------------------------------------------------
    # Lateral Movement
    # ---------------------------------------------------------
    if destination_port in REMOTE_ACCESS_PORTS:
        stages.append({
            "stage": "LATERAL_MOVEMENT",
            "description": ATTACK_STAGE_MAPPINGS[
                "LATERAL_MOVEMENT"
            ]["description"],
        })

    return stages


def detect_behavioral_attack_stages(
    evidence: list[dict],
) -> list[dict]:
    """
    Identify attack stages that require multiple network events.

    Detects:
    1. Potential reconnaissance from multiple destination ports.
    2. Potential command-and-control from repeated communication
       between the same source and destination.
    """

    results = []

    grouped_events = {}

    for event in evidence:
        source_ip = event.get("source_ip")
        destination_ip = event.get("destination_ip")
        destination_port = event.get("destination_port")

        if not source_ip or not destination_ip or not destination_port:
            continue

        key = (source_ip, destination_ip)

        if key not in grouped_events:
            grouped_events[key] = []

        grouped_events[key].append(event)

    for (source_ip, destination_ip), events in grouped_events.items():

        # -----------------------------------------------------
        # Reconnaissance
        # -----------------------------------------------------
        ports = {
            event.get("destination_port")
            for event in events
            if event.get("destination_port")
        }

        if len(ports) >= 3:
            results.append({
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "observed_ports": sorted(ports),
                "stages": [
                    {
                        "stage": "RECONNAISSANCE",
                        "description": ATTACK_STAGE_MAPPINGS[
                            "RECONNAISSANCE"
                        ]["description"],
                    }
                ],
            })

        # -----------------------------------------------------
        # Command and Control
        # -----------------------------------------------------
        if len(events) >= 3:
            timestamps = [
                event.get("timestamp")
                for event in events
                if event.get("timestamp") is not None
            ]

            if len(timestamps) >= 3:
                timestamps.sort()

                intervals = [
                    timestamps[index + 1] - timestamps[index]
                    for index in range(len(timestamps) - 1)
                ]

                if intervals:
                    average_interval = (
                        sum(intervals) / len(intervals)
                    )

                    interval_variation = max(
                        intervals
                    ) - min(intervals)

                    # Repeated communication with reasonably
                    # consistent timing can indicate a beacon-like
                    # communication pattern.
                    if (
                        average_interval > 0
                        and interval_variation
                        <= average_interval * 0.25
                    ):
                        results.append({
                            "source_ip": source_ip,
                            "destination_ip": destination_ip,
                            "connection_count": len(events),
                            "average_interval_seconds": round(
                                average_interval,
                                3,
                            ),
                            "stages": [
                                {
                                    "stage": "COMMAND_AND_CONTROL",
                                    "description": (
                                        ATTACK_STAGE_MAPPINGS[
                                            "COMMAND_AND_CONTROL"
                                        ]["description"]
                                    ),
                                }
                            ],
                        })

    return results