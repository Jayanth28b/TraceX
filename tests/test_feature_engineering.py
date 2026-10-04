from backend.core.feature_engineering import build_network_features


def test_build_network_features():
    evidence = [
        {
            "packet_length": 70,
            "source_port": 50000,
            "destination_port": 53,
            "destination_ip": "8.8.8.8",
            "protocol": "UDP",
            "dns_query": "example.com",
        },
        {
            "packet_length": 60,
            "source_port": 50001,
            "destination_port": 3389,
            "destination_ip": "8.8.4.4",
            "protocol": "TCP",
            "dns_query": None,
        },
    ]

    features = build_network_features(evidence)

    assert len(features) == 2
    assert len(features[0]) == 8

    # DNS + public IP + UDP
    assert features[0][1] == 1
    assert features[0][5] == 1
    assert features[0][7] == 1

    # Suspicious port + public IP + TCP
    assert features[1][4] == 1
    assert features[1][5] == 1
    assert features[1][6] == 1