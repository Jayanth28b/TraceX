import tempfile
from pathlib import Path

import streamlit as st

from backend.core.investigation import investigate_pcap
from backend.utils.html_report import generate_html_report
from backend.utils.report_writer import save_investigation_report


st.set_page_config(
    page_title="TraceX Digital Forensics",
    page_icon="🔎",
    layout="wide",
)


# =========================================================
# Header
# =========================================================

st.title("TraceX")
st.subheader("AI-Assisted Digital Forensics Platform")

st.write(
    "Upload a PCAP evidence file to perform forensic analysis, "
    "AI-assisted threat detection, behavioral analysis, risk "
    "assessment, and MITRE ATT&CK mapping."
)

st.divider()


# =========================================================
# PCAP Upload
# =========================================================

uploaded_file = st.file_uploader(
    "Upload PCAP Evidence",
    type=["pcap", "pcapng"],
)


if uploaded_file is not None:

    st.success(
        f"Evidence loaded: {uploaded_file.name}"
    )

    analyze_button = st.button(
        "🔍 Analyze Evidence",
        type="primary",
    )

    if analyze_button:

        with st.spinner(
            "TraceX is analyzing the network evidence..."
        ):

            try:

                suffix = Path(
                    uploaded_file.name
                ).suffix

                with tempfile.NamedTemporaryFile(
                    delete=False,
                    suffix=suffix,
                ) as temporary_file:

                    temporary_file.write(
                        uploaded_file.getbuffer()
                    )

                    temporary_path = temporary_file.name

                report = investigate_pcap(
                    temporary_path
                )

            except Exception as error:

                st.error(
                    "TraceX could not analyze the uploaded PCAP."
                )

                st.exception(error)

            else:

                st.success(
                    "Investigation completed successfully."
                )

                summary = report["summary"]

                # =================================================
                # Prepare downloadable reports
                # =================================================

                json_report_file = tempfile.NamedTemporaryFile(
                    delete=False,
                    suffix=".json",
                )

                json_report_file.close()

                json_report_path = save_investigation_report(
                    report,
                    json_report_file.name,
                )

                html_report_file = tempfile.NamedTemporaryFile(
                    delete=False,
                    suffix=".html",
                )

                html_report_file.close()

                html_report_path = generate_html_report(
                    report,
                    html_report_file.name,
                )

                json_report_bytes = Path(
                    json_report_path
                ).read_bytes()

                html_report_bytes = Path(
                    html_report_path
                ).read_bytes()

                st.divider()

                # =================================================
                # Report Downloads
                # =================================================

                st.header(
                    "Investigation Reports"
                )

                st.write(
                    "Export the complete investigation results "
                    "for evidence review and documentation."
                )

                download_col1, download_col2 = st.columns(2)

                with download_col1:

                    st.download_button(
                        label="⬇ Download JSON Report",
                        data=json_report_bytes,
                        file_name="TraceX_investigation_report.json",
                        mime="application/json",
                        use_container_width=True,
                    )

                with download_col2:

                    st.download_button(
                        label="⬇ Download HTML Report",
                        data=html_report_bytes,
                        file_name="TraceX_investigation_report.html",
                        mime="text/html",
                        use_container_width=True,
                    )

                # =================================================
                # Investigation Overview
                # =================================================

                st.divider()

                st.header(
                    "Investigation Overview"
                )

                col1, col2, col3, col4 = st.columns(4)

                with col1:
                    st.metric(
                        "Risk Score",
                        f"{summary['maximum_risk_score']}/100",
                    )

                with col2:
                    st.metric(
                        "Severity",
                        summary["severity"],
                    )

                with col3:
                    st.metric(
                        "Packets",
                        summary["packets_analyzed"],
                    )

                with col4:
                    st.metric(
                        "IOC Findings",
                        summary["findings_detected"],
                    )

                col5, col6, col7, col8 = st.columns(4)

                with col5:
                    st.metric(
                        "AI Anomalies",
                        summary["ai_anomalies_detected"],
                    )

                with col6:
                    st.metric(
                        "AI Threats",
                        summary["threats_classified"],
                    )

                with col7:
                    st.metric(
                        "MITRE Techniques",
                        summary[
                            "mitre_techniques_observed"
                        ],
                    )

                with col8:
                    st.metric(
                        "Behavioral Patterns",
                        summary.get(
                            "behavioral_attack_patterns",
                            0,
                        ),
                    )

                # =================================================
                # Severity Interpretation
                # =================================================

                severity = summary["severity"]

                if severity == "CRITICAL":

                    st.error(
                        "CRITICAL: High-priority network activity "
                        "requires immediate investigation."
                    )

                elif severity == "HIGH":

                    st.warning(
                        "HIGH: Suspicious activity requires "
                        "further investigation."
                    )

                elif severity == "MEDIUM":

                    st.warning(
                        "MEDIUM: Potentially suspicious activity "
                        "should be reviewed in context."
                    )

                else:

                    st.info(
                        "LOW: No high-priority malicious activity "
                        "was identified by the current analysis."
                    )

                # =================================================
                # Correlated Findings
                # =================================================

                st.divider()

                st.header(
                    "Correlated Findings"
                )

                st.caption(
                    "TraceX combines deterministic indicators, "
                    "AI analysis, attack-stage detection, and "
                    "MITRE ATT&CK mappings. These findings are "
                    "investigative observations and do not by "
                    "themselves prove compromise."
                )

                correlated_findings = report.get(
                    "correlated_findings",
                    [],
                )

                if correlated_findings:

                    for index, finding in enumerate(
                        correlated_findings,
                        start=1,
                    ):

                        event = finding["event"]

                        risk = finding["risk_score"]

                        with st.expander(
                            f"Finding {index} "
                            f"— Risk {risk}/100"
                        ):

                            st.write(
                                finding["assessment"]
                            )

                            left, right = st.columns(2)

                            with left:

                                st.write(
                                    "**Source IP**"
                                )

                                st.code(
                                    str(
                                        event.get(
                                            "source_ip"
                                        )
                                    )
                                )

                                st.write(
                                    "**Protocol**"
                                )

                                st.write(
                                    event.get(
                                        "protocol"
                                    )
                                )

                                st.write(
                                    "**Destination Port**"
                                )

                                st.write(
                                    event.get(
                                        "destination_port"
                                    )
                                )

                            with right:

                                st.write(
                                    "**Destination IP**"
                                )

                                st.code(
                                    str(
                                        event.get(
                                            "destination_ip"
                                        )
                                    )
                                )

                                st.write(
                                    "**IOC Risk**"
                                )

                                st.write(
                                    finding.get(
                                        "ioc_risk",
                                        0,
                                    )
                                )

                                st.write(
                                    "**Signals**"
                                )

                                signals = finding.get(
                                    "signals",
                                    [],
                                )

                                st.write(
                                    ", ".join(
                                        signals
                                    )
                                    if signals
                                    else "None"
                                )

                else:

                    st.info(
                        "No correlated findings detected."
                    )

                # =================================================
                # IOC Findings
                # =================================================

                st.divider()

                st.header(
                    "IOC Findings"
                )

                findings = report.get(
                    "findings",
                    [],
                )

                if findings:

                    finding_rows = []

                    for finding in findings:

                        finding_rows.append(
                            {
                                "Type":
                                    finding["type"],
                                "Value":
                                    finding["value"],
                                "Reason":
                                    finding["reason"],
                                "Risk":
                                    finding["risk_score"],
                            }
                        )

                    st.dataframe(
                        finding_rows,
                        use_container_width=True,
                    )

                else:

                    st.info(
                        "No deterministic IOC findings detected."
                    )

                # =================================================
                # Attack Stages
                # =================================================

                st.divider()

                st.header(
                    "Potential Attack Stages"
                )

                st.caption(
                    "Attack-stage classifications are investigative "
                    "hypotheses based on observable network behavior."
                )

                attack_stages = report.get(
                    "attack_stages",
                    [],
                )

                if attack_stages:

                    stage_rows = []

                    for result in attack_stages:

                        event = result.get(
                            "event",
                            {},
                        )

                        for stage in result.get(
                            "stages",
                            [],
                        ):

                            stage_rows.append(
                                {
                                    "Source":
                                        event.get(
                                            "source_ip"
                                        ),
                                    "Destination":
                                        event.get(
                                            "destination_ip"
                                        ),
                                    "Port":
                                        event.get(
                                            "destination_port"
                                        ),
                                    "Stage":
                                        stage.get(
                                            "stage"
                                        ),
                                    "Description":
                                        stage.get(
                                            "description"
                                        ),
                                }
                            )

                    if stage_rows:

                        st.dataframe(
                            stage_rows,
                            use_container_width=True,
                        )

                else:

                    st.info(
                        "No event-level attack stages detected."
                    )

                # =================================================
                # Behavioral Attack Patterns
                # =================================================

                st.divider()

                st.header(
                    "Behavioral Attack Patterns"
                )

                behavioral_patterns = report.get(
                    "behavioral_attack_stages",
                    [],
                )

                if behavioral_patterns:

                    for pattern in behavioral_patterns:

                        stages = pattern.get(
                            "stages",
                            [],
                        )

                        for stage in stages:

                            stage_name = stage.get(
                                "stage",
                                "UNKNOWN",
                            )

                            if stage_name == "COMMAND_AND_CONTROL":

                                st.warning(
                                    "Potential "
                                    "COMMAND_AND_CONTROL "
                                    "behavior detected."
                                )

                            elif stage_name == "RECONNAISSANCE":

                                st.warning(
                                    "Potential "
                                    "RECONNAISSANCE behavior "
                                    "detected."
                                )

                            else:

                                st.warning(
                                    f"Potential {stage_name} "
                                    "behavior detected."
                                )

                        st.write(
                            f"**Source:** "
                            f"{pattern.get('source_ip')}"
                        )

                        st.write(
                            f"**Destination:** "
                            f"{pattern.get('destination_ip')}"
                        )

                        if "observed_ports" in pattern:

                            st.write(
                                "**Observed Ports:** "
                                + ", ".join(
                                    str(port)
                                    for port in pattern[
                                        "observed_ports"
                                    ]
                                )
                            )

                        if "connection_count" in pattern:

                            st.write(
                                "**Connections:** "
                                f"{pattern['connection_count']}"
                            )

                        if (
                            "average_interval_seconds"
                            in pattern
                        ):

                            st.write(
                                "**Average Interval:** "
                                f"{pattern['average_interval_seconds']} "
                                "seconds"
                            )

                        st.divider()

                else:

                    st.info(
                        "No behavioral attack patterns detected."
                    )

                # =================================================
                # MITRE ATT&CK Mapping
                # =================================================

                st.header(
                    "MITRE ATT&CK Mapping"
                )

                mitre_attack = report.get(
                    "mitre_attack",
                    [],
                )

                unique_techniques = {}

                for result in mitre_attack:

                    for technique in result.get(
                        "techniques",
                        [],
                    ):

                        technique_id = technique[
                            "technique_id"
                        ]

                        if technique_id not in unique_techniques:

                            unique_techniques[
                                technique_id
                            ] = technique

                if unique_techniques:

                    mitre_rows = []

                    for technique in unique_techniques.values():

                        mitre_rows.append(
                            {
                                "Technique ID":
                                    technique[
                                        "technique_id"
                                    ],
                                "Technique":
                                    technique[
                                        "technique_name"
                                    ],
                                "Description":
                                    technique[
                                        "description"
                                    ],
                            }
                        )

                    st.dataframe(
                        mitre_rows,
                        use_container_width=True,
                    )

                else:

                    st.info(
                        "No MITRE ATT&CK techniques observed."
                    )

                # =================================================
                # Forensic Timeline
                # =================================================

                st.divider()

                st.header(
                    "Forensic Timeline"
                )

                timeline = report.get(
                    "timeline",
                    [],
                )

                if timeline:

                    timeline_rows = []

                    for event in timeline:

                        timeline_rows.append(
                            {
                                "#":
                                    event["sequence"],
                                "Timestamp":
                                    event["datetime"],
                                "Source":
                                    event["source_ip"],
                                "Destination":
                                    event["destination_ip"],
                                "Protocol":
                                    event["protocol"],
                                "Port":
                                    event["destination_port"],
                                "DNS Query":
                                    event["dns_query"],
                            }
                        )

                    st.dataframe(
                        timeline_rows,
                        use_container_width=True,
                    )

                else:

                    st.info(
                        "No timeline events available."
                    )