from backend.core.ioc_detector import detect_iocs


def test_public_ip_and_dns_are_not_automatically_ioc():
    evidence = [
        {
            "destination_ip": "8.8.8.8",
            "destination_port": 53,
            "dns_query": "example.com",
        }
    ]

    findings = detect_iocs(evidence)

    assert len(findings) == 0


def test_detect_suspicious_port():
    evidence = [
        {
            "destination_ip": "192.168.1.20",
            "destination_port": 3389,
            "dns_query": None,
        }
    ]

    findings = detect_iocs(evidence)

    assert len(findings) == 1
    assert findings[0]["risk_score"] == 50
    assert findings[0]["type"] == "NETWORK_INDICATOR"