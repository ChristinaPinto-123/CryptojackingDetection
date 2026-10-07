#!/usr/bin/env python3
"""
streamlit_app.py
----------------
Phase 5: Visual dashboard for the heuristic_analyzer.py / merge_reports.py
output.

Usage:
    streamlit run streamlit_app.py

Then upload (or point at) final_report.json produced by merge_reports.py
(or plain report.json if you haven't run the network correlation step --
the network section will just show "no data" in that case).

Requirements:
    pip install streamlit pandas plotly
"""

import json

import pandas as pd
import plotly.express as px
import streamlit as st

st.set_page_config(page_title="Memory Forensics Dashboard", layout="wide")

st.title("🧠 Memory Forensics Anomaly Dashboard")
st.caption("Volatility3-driven process & memory-region anomaly triage")

# ---------------------------------------------------------------------------
# Load report
# ---------------------------------------------------------------------------

source = st.radio("Report source", ["Upload JSON", "Local file path"], horizontal=True)

report = None
if source == "Upload JSON":
    uploaded = st.file_uploader("Upload final_report.json", type="json")
    if uploaded:
        report = json.load(uploaded)
else:
    path = st.text_input("Path to report file", value="final_report.json")
    if path:
        try:
            with open(path) as f:
                report = json.load(f)
        except FileNotFoundError:
            st.warning(f"No file found at {path}")

if report is None:
    st.info("Load a report produced by `heuristic_analyzer.py` / `merge_reports.py` to continue.")
    st.stop()

# ---------------------------------------------------------------------------
# Summary row
# ---------------------------------------------------------------------------

summary = report.get("summary", {})
c1, c2, c3, c4, c5, c6 = st.columns(6)
c1.metric("Processes (pslist)", summary.get("total_processes_pslist", 0))
c2.metric("Processes (psscan)", summary.get("total_processes_psscan", 0))
c3.metric("Hidden / unlinked procs", summary.get("hidden_process_count", 0))
c4.metric("malfind RWX hits", summary.get("malfind_hit_count", 0))
c5.metric("Network hits", summary.get("network_hit_count", 0))
c6.metric("Cross-category matches", summary.get("cross_category_match_count", 0))

st.divider()

# ---------------------------------------------------------------------------
# Process findings
# ---------------------------------------------------------------------------

st.subheader("Process Anomalies (pslist vs. psscan cross-reference)")

proc_findings = report.get("process_findings", [])
if proc_findings:
    df_proc = pd.DataFrame(proc_findings)
    df_proc["flags_str"] = df_proc["flags"].apply(lambda fl: ", ".join(fl))

    fig_proc = px.bar(
        df_proc.sort_values("score"),
        x="score", y="name", color="score",
        orientation="h",
        color_continuous_scale="Reds",
        hover_data=["pid", "ppid", "flags_str"],
        labels={"score": "Risk Score", "name": "Process"},
        title="Process risk score (higher = more suspicious)",
    )
    st.plotly_chart(fig_proc, use_container_width=True)

    st.dataframe(
        df_proc[["pid", "name", "ppid", "score", "flags_str"]],
        use_container_width=True,
        hide_index=True,
    )
else:
    st.success("No process-level anomalies flagged.")

st.divider()

# ---------------------------------------------------------------------------
# Malfind findings (heatmap-style)
# ---------------------------------------------------------------------------

st.subheader("Flagged Memory Regions (windows.malfind)")

malfind_findings = report.get("malfind_findings", [])
if malfind_findings:
    df_mal = pd.DataFrame(malfind_findings)

    fig_heat = px.density_heatmap(
        df_mal, x="process", y="score",
        nbinsy=10,
        color_continuous_scale="Inferno",
        title="Malfind hit concentration by process / severity",
    )
    st.plotly_chart(fig_heat, use_container_width=True)

    st.dataframe(df_mal, use_container_width=True, hide_index=True)
else:
    st.success("No malfind hits in this image.")

st.divider()

# ---------------------------------------------------------------------------
# Network findings (netscan + flow correlation -- cryptojacking heuristic)
# ---------------------------------------------------------------------------

st.subheader("Network Anomalies (netscan + flow correlation)")

net_findings = report.get("network_findings", [])
if net_findings:
    df_net = pd.DataFrame(net_findings)
    df_net["flags_str"] = df_net["flags"].apply(lambda fl: ", ".join(fl))

    if "duration_seconds" in df_net.columns and "packets_per_minute" in df_net.columns:
        fig_scatter = px.scatter(
            df_net, x="duration_seconds", y="packets_per_minute",
            size="score", color="score", color_continuous_scale="Oranges",
            hover_data=["pid", "process", "foreign_ip", "foreign_port", "flags_str"],
            labels={"duration_seconds": "Flow duration (s)",
                    "packets_per_minute": "Packets/minute"},
            title="Mining-like flows cluster at long duration + steady low-frequency "
                  "(top area, right side)",
        )
        st.plotly_chart(fig_scatter, use_container_width=True)

    st.dataframe(
        df_net[["pid", "process", "foreign_ip", "foreign_port", "score", "flags_str"]],
        use_container_width=True,
        hide_index=True,
    )
else:
    st.info("No network findings loaded (run network_correlator.py + merge_reports.py "
            "to populate this section).")

st.divider()

# ---------------------------------------------------------------------------
# Combined top priority alerts across ALL categories
# ---------------------------------------------------------------------------

st.subheader("Top Priority Alerts (combined across all categories)")

combined_rows = []
for row in proc_findings:
    combined_rows.append({
        "category": "process", "pid": row["pid"], "process": row.get("name"),
        "score": row["score"], "detail": ", ".join(row.get("flags", [])),
    })
for row in malfind_findings:
    combined_rows.append({
        "category": "malfind", "pid": row["pid"], "process": row.get("process"),
        "score": row["score"],
        "detail": f"Protection: {row.get('protection')}, Start VPN: {row.get('start_vpn')}",
    })
for row in net_findings:
    combined_rows.append({
        "category": "network", "pid": row["pid"], "process": row.get("process"),
        "score": row["score"], "detail": ", ".join(row.get("flags", [])),
    })

if combined_rows:
    df_combined = pd.DataFrame(combined_rows).sort_values("score", ascending=False).head(10)
    for _, row in df_combined.iterrows():
        with st.expander(f"[{row['category']}] PID {row['pid']} · {row['process']} · "
                          f"score {row['score']}"):
            st.write(row["detail"])
else:
    st.success("No anomalies flagged in any category.")
