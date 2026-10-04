from html import escape
from pathlib import Path


def generate_html_report(report: dict, output_path: str):
    """Generate a human-readable HTML investigation report."""

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    summary = report["summary"]

    risk_score = summary["maximum_risk_score"]
    severity = summary["severity"]

    findings_html = "".join(
        f"""
        <tr>
            <td>{escape(str(finding["type"]))}</td>
            <td>{escape(str(finding["value"]))}</td>
            <td>{escape(str(finding["reason"]))}</td>
            <td>{finding["risk_score"]}</td>
        </tr>
        """
        for finding in report["findings"]
    )

    timeline_html = "".join(
        f"""
        <tr>
            <td>{event["sequence"]}</td>
            <td>{escape(str(event["datetime"]))}</td>
            <td>{escape(str(event["source_ip"]))}</td>
            <td>{escape(str(event["destination_ip"]))}</td>
            <td>{escape(str(event["protocol"]))}</td>
            <td>{escape(str(event["destination_port"]))}</td>
            <td>{escape(str(event["dns_query"]))}</td>
        </tr>
        """
        for event in report["timeline"]
    )

    mitre_html = ""

    for result in report["mitre_attack"]:
        for technique in result["techniques"]:
            mitre_html += f"""
            <tr>
                <td>{escape(technique["technique_id"])}</td>
                <td>{escape(technique["technique_name"])}</td>
                <td>{escape(technique["description"])}</td>
            </tr>
            """

    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>TraceX Investigation Report</title>

    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 40px;
            background: #f5f7fa;
            color: #222;
        }}

        h1 {{
            margin-bottom: 5px;
        }}

        .subtitle {{
            color: #666;
            margin-bottom: 30px;
        }}

        .summary {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 15px;
            margin-bottom: 30px;
        }}

        .card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 6px rgba(0,0,0,0.08);
        }}

        .card h3 {{
            margin-top: 0;
            color: #666;
            font-size: 14px;
        }}

        .score {{
            font-size: 30px;
            font-weight: bold;
        }}

        section {{
            background: white;
            padding: 25px;
            margin-bottom: 25px;
            border-radius: 8px;
            box-shadow: 0 2px 6px rgba(0,0,0,0.08);
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
        }}

        th, td {{
            padding: 10px;
            border-bottom: 1px solid #ddd;
            text-align: left;
        }}

        th {{
            background: #f0f2f5;
        }}

        .severity {{
            font-weight: bold;
        }}
    </style>
</head>

<body>

<h1>TraceX Investigation Report</h1>

<div class="subtitle">
    AI-Assisted Digital Forensic Analysis
</div>

<div class="summary">

    <div class="card">
        <h3>Risk Score</h3>
        <div class="score">{risk_score}/100</div>
    </div>

    <div class="card">
        <h3>Severity</h3>
        <div class="score severity">{severity}</div>
    </div>

    <div class="card">
        <h3>Packets Analyzed</h3>
        <div class="score">{summary["packets_analyzed"]}</div>
    </div>

    <div class="card">
        <h3>AI Anomalies</h3>
        <div class="score">{summary["ai_anomalies_detected"]}</div>
    </div>

</div>

<section>
    <h2>Investigation Summary</h2>

    <p>
        <strong>IOC Findings:</strong>
        {summary["findings_detected"]}
    </p>

    <p>
        <strong>Threats Classified:</strong>
        {summary["threats_classified"]}
    </p>

    <p>
        <strong>Timeline Events:</strong>
        {summary["timeline_events"]}
    </p>

    <p>
        <strong>MITRE ATT&CK Techniques:</strong>
        {summary["mitre_techniques_observed"]}
    </p>
</section>

<section>
    <h2>Detected Findings</h2>

    <table>
        <tr>
            <th>Type</th>
            <th>Value</th>
            <th>Reason</th>
            <th>Risk</th>
        </tr>

        {findings_html}
    </table>
</section>

<section>
    <h2>Forensic Timeline</h2>

    <table>
        <tr>
            <th>#</th>
            <th>Timestamp</th>
            <th>Source</th>
            <th>Destination</th>
            <th>Protocol</th>
            <th>Port</th>
            <th>DNS Query</th>
        </tr>

        {timeline_html}
    </table>
</section>

<section>
    <h2>MITRE ATT&CK Mapping</h2>

    <table>
        <tr>
            <th>Technique ID</th>
            <th>Technique</th>
            <th>Description</th>
        </tr>

        {mitre_html}
    </table>
</section>

</body>
</html>
"""

    path.write_text(html, encoding="utf-8")

    return path