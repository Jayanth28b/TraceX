from backend.core.ai_classifier import ThreatClassifier


def test_threat_classifier():
    evidence = [
        {
            "packet_length": 100,
            "source_port": 50000,
            "destination_port": 80,
            "destination_ip": "192.168.1.20",
            "protocol": "TCP",
            "dns_query": None,
        },
        {
            "packet_length": 40,
            "source_port": 50001,
            "destination_port": 3389,
            "destination_ip": "8.8.4.4",
            "protocol": "TCP",
            "dns_query": None,
        },
    ]

    labels = [0, 1]

    classifier = ThreatClassifier()
    classifier.fit(evidence, labels)

    results = classifier.predict(evidence)

    assert len(results) == 2
    assert "is_threat" in results[0]
    assert "threat_probability" in results[0]