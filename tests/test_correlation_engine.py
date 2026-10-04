from backend.core.correlation_engine import correlate_event


def test_correlate_event_combines_security_signals():
    event = {
        "destination_ip": "192.168.1.20",
        "destination_port": 3389,
    }

    event_risk = {
        "risk_score": 60,
        "ioc_risk": 50,
        "is_anomaly": True,
        "anomaly_score": -0.12,
        "is_threat": True,
        "threat_probability": 0.82,
    }

    attack_stages = [
        {
            "event": event,
            "stages": [
                {
                    "stage": "LATERAL_MOVEMENT",
                }
            ],
        }
    ]

    mitre_techniques = [
        {
            "event": event,
            "techniques": [
                {
                    "technique_id": "T1021.001",
                }
            ],
        }
    ]

    result = correlate_event(
        event,
        event_risk,
        attack_stages,
        mitre_techniques,
    )

    assert result["risk_score"] == 60

    assert "IOC" in result["signals"]
    assert "AI_ANOMALY" in result["signals"]
    assert "AI_THREAT" in result["signals"]
    assert "ATTACK_STAGE" in result["signals"]
    assert "MITRE_MAPPING" in result["signals"]

    assert result["ai_anomaly"]["detected"] is True
    assert result["ai_threat"]["detected"] is True

    assert (
        result["attack_stages"][0]["stage"]
        == "LATERAL_MOVEMENT"
    )

    assert (
        result["mitre_techniques"][0]["technique_id"]
        == "T1021.001"
    )

    assert result["assessment"].startswith(
        "Suspicious activity requiring further investigation."
    )

    assert (
        "suspicious network indicator"
        in result["assessment"]
    )

    assert (
        "AI threat classifier"
        in result["assessment"]
    )

    assert (
        "AI anomaly detector"
        in result["assessment"]
    )

    assert (
        "LATERAL_MOVEMENT"
        in result["assessment"]
    )

    assert (
        "MITRE ATT&CK mapping"
        in result["assessment"]
    )


def test_correlate_event_low_risk():
    event = {
        "destination_ip": "192.168.1.20",
        "destination_port": 80,
    }

    event_risk = {
        "risk_score": 10,
        "ioc_risk": 0,
        "is_anomaly": False,
        "anomaly_score": 0.12,
        "is_threat": False,
        "threat_probability": 0.05,
    }

    result = correlate_event(
        event,
        event_risk,
        [],
        [],
    )

    assert result["risk_score"] == 10
    assert result["signals"] == []

    assert (
        result["assessment"]
        == "Low-risk network activity."
    )