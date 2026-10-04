import json

from backend.utils.evidence_writer import save_evidence


def test_save_evidence(tmp_path):
    evidence = [
        {
            "source_ip": "192.168.1.10",
            "destination_ip": "8.8.8.8",
            "protocol": "UDP",
        }
    ]

    output = tmp_path / "evidence.json"

    save_evidence(evidence, output)

    assert output.exists()

    with output.open(encoding="utf-8") as file:
        saved = json.load(file)

    assert saved[0]["source_ip"] == "192.168.1.10"