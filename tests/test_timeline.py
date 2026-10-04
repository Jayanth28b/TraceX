from backend.core.timeline import build_timeline


def test_build_timeline_orders_events_by_timestamp():
    evidence = [
        {
            "timestamp": 3.0,
            "source_ip": "192.168.1.3",
            "destination_ip": "192.168.1.4",
            "protocol": "TCP",
            "source_port": 50002,
            "destination_port": 80,
            "dns_query": None,
            "packet_length": 60,
        },
        {
            "timestamp": 1.0,
            "source_ip": "192.168.1.1",
            "destination_ip": "8.8.8.8",
            "protocol": "UDP",
            "source_port": 50000,
            "destination_port": 53,
            "dns_query": "example.com",
            "packet_length": 70,
        },
        {
            "timestamp": 2.0,
            "source_ip": "192.168.1.2",
            "destination_ip": "192.168.1.3",
            "protocol": "TCP",
            "source_port": 50001,
            "destination_port": 80,
            "dns_query": None,
            "packet_length": 54,
        },
    ]

    timeline = build_timeline(evidence)

    assert len(timeline) == 3
    assert timeline[0]["timestamp"] == 1.0
    assert timeline[1]["timestamp"] == 2.0
    assert timeline[2]["timestamp"] == 3.0

    assert timeline[0]["sequence"] == 1
    assert timeline[1]["sequence"] == 2
    assert timeline[2]["sequence"] == 3

    assert timeline[0]["dns_query"] == "example.com"
    assert timeline[1]["protocol"] == "TCP"