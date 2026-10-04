from backend.core.investigation import investigate_pcap


def test_investigate_sample_pcap():
    report = investigate_pcap("samples/test_capture.pcap")

    assert report["summary"]["packets_analyzed"] == 3
    assert report["summary"]["findings_detected"] > 0
    assert "ai_analysis" in report
    assert len(report["ai_analysis"]) == 3
    assert "is_anomaly" in report["ai_analysis"][0]