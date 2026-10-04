from backend.core.mitre_mapper import (
    map_event_to_mitre,
    map_evidence_to_mitre,
)


def test_dns_maps_to_dns_technique():
    event = {
        "destination_port": 53,
        "dns_query": "example.com",
    }

    mappings = map_event_to_mitre(event)

    assert len(mappings) == 1
    assert mappings[0]["technique_id"] == "T1071.004"


def test_http_maps_to_web_protocols():
    event = {
        "destination_port": 80,
        "dns_query": None,
    }

    mappings = map_event_to_mitre(event)

    assert len(mappings) == 1
    assert mappings[0]["technique_id"] == "T1071.001"


def test_rdp_maps_to_remote_services():
    event = {
        "destination_port": 3389,
        "dns_query": None,
    }

    mappings = map_event_to_mitre(event)

    assert len(mappings) == 1
    assert mappings[0]["technique_id"] == "T1021.001"


def test_normal_event_has_no_mitre_mapping():
    event = {
        "destination_port": 50001,
        "dns_query": None,
    }

    mappings = map_event_to_mitre(event)

    assert mappings == []


def test_map_evidence_to_mitre():
    evidence = [
        {
            "destination_port": 53,
            "dns_query": "example.com",
        },
        {
            "destination_port": 80,
            "dns_query": None,
        },
    ]

    results = map_evidence_to_mitre(evidence)

    assert len(results) == 2
    assert results[0]["techniques"][0]["technique_id"] == "T1071.004"
    assert results[1]["techniques"][0]["technique_id"] == "T1071.001"