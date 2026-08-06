"""
Insider Threat Behavioral Intelligence System
Milestone 4: Security Analyst Dashboard (minimal, scoped honestly)

Run with:
    streamlit run risk_dashboard.py

Reads user_risk_scores.csv directly (same data the API serves).
Scope note shown on the page itself - not hidden in a code comment -
so anyone viewing the dashboard sees the same disclosure as the report.
"""

import streamlit as st
import pandas as pd
import os

st.set_page_config(page_title="Insider Risk Dashboard", layout="wide")

CSV_PATH = os.path.join(os.path.dirname(__file__), "user_risk_scores.csv")

st.title("Insider Threat — Security Analyst Dashboard")

st.warning(
    "**Scope note:** Risk scores below reflect **Behavioral Anomalies only** "
    "(one of 5 categories in the full spec). Privilege Misuse, Data Access "
    "Violations, Access Pattern Deviations, and Historical Security Events "
    "are not computed — no log data exists for those categories in this project."
)

if not os.path.exists(CSV_PATH):
    st.error(f"{CSV_PATH} not found. Run risk_scoring_engine.py first.")
    st.stop()

df = pd.read_csv(CSV_PATH)

# --- Summary metrics ---
col1, col2, col3, col4 = st.columns(4)
counts = df["risk_category"].value_counts()
col1.metric("Critical", int(counts.get("Critical", 0)))
col2.metric("High", int(counts.get("High", 0)))
col3.metric("Medium", int(counts.get("Medium", 0)))
col4.metric("Low", int(counts.get("Low", 0)))

st.divider()

# --- Filter ---
categories = ["All"] + sorted(df["risk_category"].unique().tolist())
selected = st.selectbox("Filter by risk category", categories)

filtered = df if selected == "All" else df[df["risk_category"] == selected]
filtered = filtered.sort_values("insider_risk_score", ascending=False)

# --- Color coding ---
def color_risk(val):
    colors = {
        "Critical": "background-color: #ff4b4b; color: white;",
        "High": "background-color: #ffa64b; color: black;",
        "Medium": "background-color: #ffe14b; color: black;",
        "Low": "background-color: #a6e37e; color: black;",
    }
    return colors.get(val, "")

display_cols = [
    "user", "insider_risk_score", "risk_category",
    "anomalous_day_count", "mean_anomaly_score", "worst_anomaly_score",
    "most_common_anomaly_trigger",
]

styled = filtered[display_cols].style.applymap(color_risk, subset=["risk_category"])
st.dataframe(styled, use_container_width=True, height=500)

st.caption(
    f"{len(filtered)} of {len(df)} users shown. "
    "Risk category is relative to this user population, not an absolute scale."
)
