from backend.core.investigation import investigate_pcap


def test_investigate_sample_pcap():
    report = investigate_pcap("samples/test_capture.pcap")

    assert report["summary"]["packets_analyzed"] == 3
    assert report["summary"]["findings_detected"] == 0

    assert "ai_analysis" in report
    assert len(report["ai_analysis"]) == 3
    assert "is_anomaly" in report["ai_analysis"][0]

    assert "threat_classification" in report
    assert len(report["threat_classification"]) == 3

    assert "event_risk" in report
    assert len(report["event_risk"]) == 3

    assert "maximum_risk_score" in report["summary"]