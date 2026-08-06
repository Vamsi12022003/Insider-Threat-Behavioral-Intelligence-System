"""
Insider Threat Behavioral Intelligence System
Milestone 3: Insider Risk Scoring Engine

SCOPE / HONESTY NOTE
--------------------
The project spec's weighted risk model calls for 5 categories:
    Behavioral Anomalies      35%
    Privilege Misuse          25%
    Data Access Violations    20%
    Access Pattern Deviations 10%
    Historical Security Events 10%

Only "Behavioral Anomalies" has real underlying data (anomaly_report.csv,
produced by Milestone 2's Isolation Forest pipeline over logon/device logs).
There is no privilege-change log, no file/data-access log, and no historical
incident log in this project. Rather than invent numbers for those 4
categories, this engine scores users on Behavioral Anomalies ONLY and
documents the other categories as "not computed - no data source" in the
output. This is a deliberate, disclosed limitation, not an oversight.

If/when logs for the other categories become available (e.g. file access,
privilege change events), the WEIGHTS dict and score calculation below are
structured so those categories can be added without a rewrite.
"""

import pandas as pd
import numpy as np

INPUT_REPORT = "anomaly_report.csv"
OUTPUT_RISK_SCORES = "user_risk_scores.csv"

# Only category with real data right now. Kept as a dict so it's obvious
# how/where to plug in the other 4 categories later.
WEIGHTS = {
    "behavioral_anomalies": 1.00,   # 100% of computed score (spec says 35%)
    # "privilege_misuse":        0.25,  # NOT COMPUTED - no privilege log
    # "data_access_violations":  0.20,  # NOT COMPUTED - no file/data-access log
    # "access_pattern_deviation":0.10,  # NOT COMPUTED - no separate access log
    # "historical_security":     0.10,  # NOT COMPUTED - no incident history log
}

RISK_BUCKETS = [
    (0.75, "Critical"),
    (0.50, "High"),
    (0.25, "Medium"),
    (0.00, "Low"),
]


def load_anomalies():
    df = pd.read_csv(INPUT_REPORT, parse_dates=["day"])
    return df


def compute_behavioral_anomaly_component(df):
    """
    Aggregate per-user anomaly signal into a single 0-1 'badness' score.

    anomaly_score from Isolation Forest: more negative = more anomalous.
    We use, per user:
      - count of anomalous days
      - mean anomaly_score (most negative = worse)
    then combine and min-max normalize across users to 0-1.
    """
    agg = df.groupby("user").agg(
        anomalous_day_count=("day", "nunique"),
        mean_anomaly_score=("anomaly_score", "mean"),
        worst_anomaly_score=("anomaly_score", "min"),
    ).reset_index()

    # Flip sign so higher = worse, then normalize each component 0-1
    agg["severity_raw"] = -agg["mean_anomaly_score"]
    agg["worst_raw"] = -agg["worst_anomaly_score"]

    def normalize(s):
        rng = s.max() - s.min()
        if rng == 0:
            return pd.Series(0.0, index=s.index)
        return (s - s.min()) / rng

    freq_norm = normalize(agg["anomalous_day_count"])
    severity_norm = normalize(agg["severity_raw"])
    worst_norm = normalize(agg["worst_raw"])

    # Blend: how often + how bad on average + worst single day
    agg["behavioral_anomalies"] = (
        0.4 * freq_norm + 0.4 * severity_norm + 0.2 * worst_norm
    )

    return agg[["user", "anomalous_day_count", "mean_anomaly_score",
                "worst_anomaly_score", "behavioral_anomalies"]]


def compute_insider_risk_score(agg):
    agg = agg.copy()
    agg["insider_risk_score"] = agg["behavioral_anomalies"] * WEIGHTS["behavioral_anomalies"]

    def bucket(score):
        for threshold, label in RISK_BUCKETS:
            if score >= threshold:
                return label
        return "Low"

    agg["risk_category"] = agg["insider_risk_score"].apply(bucket)

    # Explicit disclosure columns - so the CSV itself documents the limitation
    for missing_cat in ["privilege_misuse_indicators", "data_access_violations",
                         "access_pattern_deviations", "historical_security_events"]:
        agg[missing_cat] = "NOT COMPUTED - no data source"

    return agg


def generate_top_reasons(df, agg):
    """Attach each user's most common anomaly trigger for investigator context."""
    top_reason = (
        df.groupby("user")["primary_reason"]
        .agg(lambda x: x.value_counts().index[0])
        .reset_index()
        .rename(columns={"primary_reason": "most_common_anomaly_trigger"})
    )
    return pd.merge(agg, top_reason, on="user", how="left")


def main():
    print("Loading anomaly report...")
    df = load_anomalies()
    print(f"  {len(df):,} anomalous user-day records, {df['user'].nunique()} unique users")

    print("\nComputing behavioral anomaly component (only scoreable category)...")
    agg = compute_behavioral_anomaly_component(df)

    print("Computing insider risk scores...")
    agg = compute_insider_risk_score(agg)
    agg = generate_top_reasons(df, agg)

    agg = agg.sort_values("insider_risk_score", ascending=False)

    ordered_cols = [
        "user", "insider_risk_score", "risk_category",
        "anomalous_day_count", "mean_anomaly_score", "worst_anomaly_score",
        "most_common_anomaly_trigger",
        "privilege_misuse_indicators", "data_access_violations",
        "access_pattern_deviations", "historical_security_events",
    ]
    agg[ordered_cols].to_csv(OUTPUT_RISK_SCORES, index=False)

    print(f"\nSaved: {OUTPUT_RISK_SCORES} ({len(agg)} users)")
    print("\nRisk category breakdown:")
    print(agg["risk_category"].value_counts().to_string())
    print("\nTop 10 highest-risk users:")
    print(agg[ordered_cols[:6]].head(10).to_string(index=False))

    print("\nNOTE: Score reflects Behavioral Anomalies only (100% weight applied here).")
    print("Per the project spec's 5-category model, Privilege Misuse, Data Access")
    print("Violations, Access Pattern Deviations, and Historical Security Events")
    print("are NOT included - no underlying log data exists for them in this project.")


if __name__ == "__main__":
    main()
