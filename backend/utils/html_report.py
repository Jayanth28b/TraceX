from html import escape
from pathlib import Path


def generate_html_report(report: dict, output_path: str):
    """Generate a human-readable HTML investigation report."""

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    summary = report["summary"]

    risk_score = summary["maximum_risk_score"]
    severity = summary["severity"]

    # ---------------------------------------------------------
    # Detected IOC findings
    # ---------------------------------------------------------

    findings_html = ""

    if report["findings"]:
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
    else:
        findings_html = """
        <tr>
            <td colspan="4">No deterministic IOC findings detected.</td>
        </tr>
        """

    # ---------------------------------------------------------
    # Correlated findings
    # ---------------------------------------------------------

    correlated_html = ""

    for result in report.get("correlated_findings", []):
        event = result.get("event", {})

        source_ip = event.get("source_ip")
        destination_ip = event.get("destination_ip")
        protocol = event.get("protocol")
        destination_port = event.get("destination_port")

        signals = ", ".join(
            result.get("signals", [])
        )

        correlated_html += f"""
        <tr>
            <td>{escape(str(source_ip))}</td>
            <td>{escape(str(destination_ip))}</td>
            <td>{escape(str(protocol))}</td>
            <td>{escape(str(destination_port))}</td>
            <td>{result.get("risk_score", 0)}</td>
            <td>{escape(signals or "None")}</td>
            <td>{escape(str(result.get("assessment", "")))}</td>
        </tr>
        """

    if not correlated_html:
        correlated_html = """
        <tr>
            <td colspan="7">No correlated findings available.</td>
        </tr>
        """

    # ---------------------------------------------------------
    # Attack stages
    # ---------------------------------------------------------

    attack_stage_html = ""

    for result in report.get("attack_stages", []):
        event = result.get("event", {})

        source_ip = event.get("source_ip")
        destination_ip = event.get("destination_ip")
        destination_port = event.get("destination_port")

        for stage in result.get("stages", []):
            attack_stage_html += f"""
            <tr>
                <td>{escape(str(source_ip))}</td>
                <td>{escape(str(destination_ip))}</td>
                <td>{escape(str(destination_port))}</td>
                <td>{escape(str(stage.get("stage", "")))}</td>
                <td>{escape(str(stage.get("description", "")))}</td>
            </tr>
            """

    if not attack_stage_html:
        attack_stage_html = """
        <tr>
            <td colspan="5">No event-level attack stages detected.</td>
        </tr>
        """

    # ---------------------------------------------------------
    # Behavioral attack patterns
    # ---------------------------------------------------------

    behavioral_stage_html = ""

    for result in report.get(
        "behavioral_attack_stages",
        [],
    ):
        source_ip = result.get("source_ip")
        destination_ip = result.get("destination_ip")

        observed_ports = ", ".join(
            str(port)
            for port in result.get(
                "observed_ports",
                [],
            )
        )

        connection_count = result.get(
            "connection_count",
            "",
        )

        average_interval = result.get(
            "average_interval_seconds",
            "",
        )

        for stage in result.get("stages", []):
            behavioral_stage_html += f"""
            <tr>
                <td>{escape(str(source_ip))}</td>
                <td>{escape(str(destination_ip))}</td>
                <td>{escape(observed_ports)}</td>
                <td>{escape(str(connection_count))}</td>
                <td>{escape(str(average_interval))}</td>
                <td>{escape(str(stage.get("stage", "")))}</td>
                <td>{escape(str(stage.get("description", "")))}</td>
            </tr>
            """

    if not behavioral_stage_html:
        behavioral_stage_html = """
        <tr>
            <td colspan="7">
                No multi-event behavioral attack patterns detected.
            </td>
        </tr>
        """

    # ---------------------------------------------------------
    # Forensic timeline
    # ---------------------------------------------------------

    timeline_html = ""

    for event in report["timeline"]:
        timeline_html += f"""
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

    # ---------------------------------------------------------
    # MITRE ATT&CK mapping
    # ---------------------------------------------------------

    mitre_html = ""

    for result in report["mitre_attack"]:
        for technique in result["techniques"]:
            mitre_html += f"""
            <tr>
                <td>{escape(str(technique["technique_id"]))}</td>
                <td>{escape(str(technique["technique_name"]))}</td>
                <td>{escape(str(technique["description"]))}</td>
            </tr>
            """

    if not mitre_html:
        mitre_html = """
        <tr>
            <td colspan="3">
                No MITRE ATT&CK techniques observed.
            </td>
        </tr>
        """

    # ---------------------------------------------------------
    # HTML document
    # ---------------------------------------------------------

    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport"
          content="width=device-width, initial-scale=1.0">

    <title>TraceX Investigation Report</title>

    <style>

        body {{
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 30px;
            background: #f5f7fa;
            color: #222;
        }}

        .container {{
            max-width: 1500px;
            margin: auto;
        }}

        header {{
            margin-bottom: 30px;
        }}

        h1 {{
            margin-bottom: 5px;
        }}

        .subtitle {{
            color: #666;
        }}

        section {{
            background: white;
            padding: 25px;
            margin-bottom: 25px;
            border-radius: 8px;
            box-shadow: 0 2px 6px rgba(0,0,0,0.08);
            overflow-x: auto;
        }}

        .summary {{
            display: grid;
            grid-template-columns:
                repeat(auto-fit, minmax(180px, 1fr));
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
            font-size: 28px;
            font-weight: bold;
        }}

        .severity {{
            font-weight: bold;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            min-width: 700px;
        }}

        th, td {{
            padding: 10px;
            border-bottom: 1px solid #ddd;
            text-align: left;
            vertical-align: top;
        }}

        th {{
            background: #f0f2f5;
        }}

        tr:hover {{
            background: #fafafa;
        }}

        .note {{
            color: #666;
            font-size: 14px;
            margin-top: 10px;
        }}

    </style>
</head>

<body>

<div class="container">

<header>
    <h1>TraceX Investigation Report</h1>

    <div class="subtitle">
        AI-Assisted Digital Forensic Analysis
    </div>
</header>

<!-- ===================================================== -->
<!-- SUMMARY CARDS                                         -->
<!-- ===================================================== -->

<div class="summary">

    <div class="card">
        <h3>Maximum Risk Score</h3>
        <div class="score">
            {risk_score}/100
        </div>
    </div>

    <div class="card">
        <h3>Severity</h3>
        <div class="score severity">
            {escape(str(severity))}
        </div>
    </div>

    <div class="card">
        <h3>Packets Analyzed</h3>
        <div class="score">
            {summary["packets_analyzed"]}
        </div>
    </div>

    <div class="card">
        <h3>IOC Findings</h3>
        <div class="score">
            {summary["findings_detected"]}
        </div>
    </div>

    <div class="card">
        <h3>AI Anomalies</h3>
        <div class="score">
            {summary["ai_anomalies_detected"]}
        </div>
    </div>

    <div class="card">
        <h3>Threats Classified</h3>
        <div class="score">
            {summary["threats_classified"]}
        </div>
    </div>

    <div class="card">
        <h3>Attack Stage Events</h3>
        <div class="score">
            {summary.get("attack_stage_events", 0)}
        </div>
    </div>

    <div class="card">
        <h3>Behavioral Patterns</h3>
        <div class="score">
            {summary.get("behavioral_attack_patterns", 0)}
        </div>
    </div>

</div>

<!-- ===================================================== -->
<!-- INVESTIGATION SUMMARY                                 -->
<!-- ===================================================== -->

<section>

    <h2>Investigation Summary</h2>

    <p>
        <strong>Packets Analyzed:</strong>
        {summary["packets_analyzed"]}
    </p>

    <p>
        <strong>IOC Findings:</strong>
        {summary["findings_detected"]}
    </p>

    <p>
        <strong>AI Anomalies:</strong>
        {summary["ai_anomalies_detected"]}
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

    <p>
        <strong>Attack Stage Events:</strong>
        {summary.get("attack_stage_events", 0)}
    </p>

    <p>
        <strong>Behavioral Attack Patterns:</strong>
        {summary.get("behavioral_attack_patterns", 0)}
    </p>

    <p>
        <strong>Correlated Findings:</strong>
        {summary.get("correlated_findings", 0)}
    </p>

</section>

<!-- ===================================================== -->
<!-- CORRELATED FINDINGS                                   -->
<!-- ===================================================== -->

<section>

    <h2>Correlated Findings</h2>

    <p class="note">
        TraceX correlates deterministic, AI, behavioral, and
        MITRE signals. These findings represent investigative
        observations and do not by themselves prove compromise.
    </p>

    <table>

        <tr>
            <th>Source</th>
            <th>Destination</th>
            <th>Protocol</th>
            <th>Port</th>
            <th>Risk</th>
            <th>Signals</th>
            <th>Assessment</th>
        </tr>

        {correlated_html}

    </table>

</section>

<!-- ===================================================== -->
<!-- IOC FINDINGS                                          -->
<!-- ===================================================== -->

<section>

    <h2>Detected IOC Findings</h2>

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

<!-- ===================================================== -->
<!-- ATTACK STAGES                                         -->
<!-- ===================================================== -->

<section>

    <h2>Potential Attack Stages</h2>

    <p class="note">
        Attack-stage mappings are investigative hypotheses
        based on observable network behavior.
    </p>

    <table>

        <tr>
            <th>Source</th>
            <th>Destination</th>
            <th>Port</th>
            <th>Stage</th>
            <th>Description</th>
        </tr>

        {attack_stage_html}

    </table>

</section>

<!-- ===================================================== -->
<!-- BEHAVIORAL ATTACK PATTERNS                            -->
<!-- ===================================================== -->

<section>

    <h2>Behavioral Attack Patterns</h2>

    <p class="note">
        These detections use multiple network events to identify
        potential reconnaissance or command-and-control behavior.
    </p>

    <table>

        <tr>
            <th>Source</th>
            <th>Destination</th>
            <th>Observed Ports</th>
            <th>Connections</th>
            <th>Avg. Interval (s)</th>
            <th>Stage</th>
            <th>Description</th>
        </tr>

        {behavioral_stage_html}

    </table>

</section>

<!-- ===================================================== -->
<!-- FORENSIC TIMELINE                                    -->
<!-- ===================================================== -->

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

<!-- ===================================================== -->
<!-- MITRE ATT&CK                                         -->
<!-- ===================================================== -->

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

</div>

</body>
</html>
"""

    path.write_text(
        html,
        encoding="utf-8",
    )

    return path