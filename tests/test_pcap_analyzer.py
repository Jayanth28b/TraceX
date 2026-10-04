from backend.core.pcap_analyzer import analyze_pcap


def test_analyze_sample_pcap():
    evidence = analyze_pcap("samples/test_capture.pcap")

    assert len(evidence) == 3
    assert evidence[0]["source_ip"] == "192.168.1.10"
    assert evidence[0]["dns_query"] == "example.com"