from backend.core.ai_anomaly_detector import AnomalyDetector


def test_anomaly_detector():
    evidence = [
        {
            "packet_length": 60,
            "source_port": 50000,
            "destination_port": 80,
        },
        {
            "packet_length": 70,
            "source_port": 50001,
            "destination_port": 80,
        },
        {
            "packet_length": 65,
            "source_port": 50002,
            "destination_port": 80,
        },
    ]

    detector = AnomalyDetector(contamination=0.1)
    detector.fit(evidence)

    results = detector.predict(evidence)

    assert len(results) == 3
    assert "is_anomaly" in results[0]
    assert "anomaly_score" in results[0]