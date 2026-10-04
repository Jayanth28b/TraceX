from backend.parsers.pcap_parser import load_pcap


def test_pcap_parser_import():
    assert callable(load_pcap)