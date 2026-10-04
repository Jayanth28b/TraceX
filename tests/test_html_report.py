from backend.utils.html_report import generate_html_report


def test_generate_html_report(tmp_path):
    report = {
        "findings": [],
        "timeline": [
            {
                "sequence": 1,
                "datetime": "2026-10-04T08:12:50+00:00",
                "source_ip": "192.168.1.10",
                "destination_ip": "8.8.8.8",
                "protocol": "UDP",
                "destination_port": 53,
                "dns_query": "example.com",
            }
        ],
        "mitre_attack": [
            {
                "event": {},
                "techniques": [
                    {
                        "technique_id": "T1071.004",
                        "technique_name": "DNS",
                        "description": "DNS traffic observed.",
                    }
                ],
            }
        ],
        "summary": {
            "maximum_risk_score": 22.1,
            "severity": "LOW",
            "packets_analyzed": 1,
            "findings_detected": 0,
            "ai_anomalies_detected": 1,
            "threats_classified": 0,
            "timeline_events": 1,
            "mitre_techniques_observed": 1,
        },
    }

    output_path = tmp_path / "report.html"

    result = generate_html_report(
        report,
        str(output_path),
    )

    assert result == output_path
    assert output_path.exists()

    content = output_path.read_text(encoding="utf-8")

    assert "TraceX Investigation Report" in content
    assert "22.1/100" in content
    assert "LOW" in content
    assert "T1071.004" in content
    assert "example.com" in content