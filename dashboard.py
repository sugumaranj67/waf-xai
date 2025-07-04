# dashboard.py

import os
import json
from datetime import datetime

import streamlit as st
import pandas as pd
import plotly.express as px

LOG_FILE = "logs/alerts.json"

st.set_page_config(page_title="WAF-XAI Dashboard", layout="wide")
st.title("🛡️ WAF-XAI Threat Dashboard")
st.markdown("Real-time visualization of regex & ML detections")

# ─── Load and parse logs ───────────────────────────────────────────────────────
if not os.path.exists(LOG_FILE):
    st.warning("No alerts found. Trigger some malicious and benign requests first.")
    st.stop()

with open(LOG_FILE, "r") as f:
    lines = [line.strip() for line in f if line.strip()]

if not lines:
    st.info("Log file is empty.")
    st.stop()

records = [json.loads(line) for line in lines]
df = pd.DataFrame(records)

# Ensure required columns exist
for col in (
    "timestamp",
    "attack_type",
    "source",
    "severity",
    "confidence",
    "client_ip",
    "explanation",
):
    if col not in df.columns:
        df[col] = None

# Convert timestamp & derive date
df["timestamp"] = pd.to_datetime(df["timestamp"])
df["date"] = df["timestamp"].dt.date

# ─── Sidebar filters ──────────────────────────────────────────────────────────
st.sidebar.header("🔍 Filters")

attack_types = st.sidebar.multiselect(
    "Attack Type",
    options=sorted(df["attack_type"].fillna("benign").unique()),
    default=sorted(df["attack_type"].fillna("benign").unique()),
)

sources = st.sidebar.multiselect(
    "Detection Source",
    options=sorted(df["source"].fillna("unknown").unique()),
    default=sorted(df["source"].fillna("unknown").unique()),
)

severities = st.sidebar.multiselect(
    "Severity",
    options=sorted(df["severity"].fillna("unknown").unique()),
    default=sorted(df["severity"].fillna("unknown").unique()),
)

conf_min, conf_max = st.sidebar.slider(
    "Confidence Range", min_value=0.0, max_value=1.0, value=(0.0, 1.0), step=0.01
)

# Apply filters
filtered = df[
    df["attack_type"].fillna("benign").isin(attack_types)
    & df["source"].fillna("unknown").isin(sources)
    & df["severity"].fillna("unknown").isin(severities)
    & df["confidence"].between(conf_min, conf_max)
]

# ─── Top‐line metrics ─────────────────────────────────────────────────────────
col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Alerts", len(filtered))
col2.metric("SQLi", int((filtered["attack_type"] == "SQLi").sum()))
col3.metric("XSS", int((filtered["attack_type"] == "XSS").sum()))
col4.metric("Benign", int((filtered["attack_type"] == "benign").sum()))

st.markdown("---")

# ─── Charts: distribution & breakdown ─────────────────────────────────────────
c1, c2, c3 = st.columns(3)

with c1:
    fig = px.pie(
        filtered, names="attack_type", title="Attack Type Distribution", hole=0.3
    )
    st.plotly_chart(fig, use_container_width=True)

with c2:
    fig = px.pie(filtered, names="source", title="Detection Source", hole=0.3)
    st.plotly_chart(fig, use_container_width=True)

with c3:
    fig = px.histogram(
        filtered,
        x="confidence",
        nbins=20,
        title="Confidence Scores",
        labels={"confidence": "ML Confidence"},
    )
    st.plotly_chart(fig, use_container_width=True)

# ─── Severity breakdown ───────────────────────────────────────────────────────
st.markdown("### 🔥 Severity Breakdown by Attack Type")
fig_sev = px.histogram(
    filtered,
    x="severity",
    color="attack_type",
    barmode="group",
    title="Severity × Attack Type",
)
st.plotly_chart(fig_sev, use_container_width=True)

# ─── Timeline ─────────────────────────────────────────────────────────────────
st.markdown("### 📈 Alerts Over Time")
time_series = filtered.groupby("date").size().reset_index(name="count")
fig_time = px.line(
    time_series, x="date", y="count", markers=True, title="Number of Alerts per Day"
)
st.plotly_chart(fig_time, use_container_width=True)

# ─── Data export & table ─────────────────────────────────────────────────────
st.markdown("### 📋 Alert Log Details")
st.download_button(
    label="📥 Download Filtered Data as CSV",
    data=filtered.to_csv(index=False).encode("utf-8"),
    file_name="waf_xai_alerts.csv",
    mime="text/csv",
)

st.dataframe(
    filtered[
        [
            "timestamp",
            "client_ip",
            "attack_type",
            "source",
            "severity",
            "confidence",
            "explanation",
        ]
    ].sort_values("timestamp", ascending=False),
    use_container_width=True,
)
