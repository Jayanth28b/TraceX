from backend.core.attack_stage import (
    detect_attack_stages,
    detect_behavioral_attack_stages,
)


def test_normal_dns_has_no_attack_stage():
    event = {
        "destination_port": 53,
    }

    stages = detect_attack_stages(event)

    assert stages == []


def test_rdp_maps_to_lateral_movement():
    event = {
        "destination_port": 3389,
    }

    stages = detect_attack_stages(event)

    assert len(stages) == 1
    assert stages[0]["stage"] == "LATERAL_MOVEMENT"


def test_smb_maps_to_lateral_movement():
    event = {
        "destination_port": 445,
    }

    stages = detect_attack_stages(event)

    assert len(stages) == 1
    assert stages[0]["stage"] == "LATERAL_MOVEMENT"


def test_suspicious_port_maps_to_initial_access():
    event = {
        "destination_port": 4444,
    }

    stages = detect_attack_stages(event)

    assert len(stages) == 1
    assert stages[0]["stage"] == "INITIAL_ACCESS"


def test_multiple_ports_indicate_potential_reconnaissance():
    evidence = [
        {
            "source_ip": "192.168.1.10",
            "destination_ip": "192.168.1.20",
            "destination_port": 21,
        },
        {
            "source_ip": "192.168.1.10",
            "destination_ip": "192.168.1.20",
            "destination_port": 22,
        },
        {
            "source_ip": "192.168.1.10",
            "destination_ip": "192.168.1.20",
            "destination_port": 80,
        },
    ]

    results = detect_behavioral_attack_stages(evidence)

    assert len(results) == 1
    assert results[0]["source_ip"] == "192.168.1.10"
    assert results[0]["destination_ip"] == "192.168.1.20"
    assert results[0]["observed_ports"] == [21, 22, 80]
    assert results[0]["stages"][0]["stage"] == "RECONNAISSANCE"


def test_two_ports_are_not_enough_for_reconnaissance():
    evidence = [
        {
            "source_ip": "192.168.1.10",
            "destination_ip": "192.168.1.20",
            "destination_port": 22,
        },
        {
            "source_ip": "192.168.1.10",
            "destination_ip": "192.168.1.20",
            "destination_port": 80,
        },
    ]

    results = detect_behavioral_attack_stages(evidence)

    assert results == []
def test_repeated_regular_connections_indicate_potential_c2():
    evidence = [
        {
            "source_ip": "192.168.1.10",
            "destination_ip": "203.0.113.10",
            "destination_port": 443,
            "timestamp": 1000,
        },
        {
            "source_ip": "192.168.1.10",
            "destination_ip": "203.0.113.10",
            "destination_port": 443,
            "timestamp": 1010,
        },
        {
            "source_ip": "192.168.1.10",
            "destination_ip": "203.0.113.10",
            "destination_port": 443,
            "timestamp": 1020,
        },
    ]

    results = detect_behavioral_attack_stages(evidence)

    assert len(results) == 1
    assert results[0]["connection_count"] == 3
    assert results[0]["average_interval_seconds"] == 10.0
    assert results[0]["stages"][0]["stage"] == "COMMAND_AND_CONTROL"


def test_irregular_connections_are_not_classified_as_c2():
    evidence = [
        {
            "source_ip": "192.168.1.10",
            "destination_ip": "203.0.113.10",
            "destination_port": 443,
            "timestamp": 1000,
        },
        {
            "source_ip": "192.168.1.10",
            "destination_ip": "203.0.113.10",
            "destination_port": 443,
            "timestamp": 1010,
        },
        {
            "source_ip": "192.168.1.10",
            "destination_ip": "203.0.113.10",
            "destination_port": 443,
            "timestamp": 1100,
        },
    ]

    results = detect_behavioral_attack_stages(evidence)

    assert results == []