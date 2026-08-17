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

Two categories have real underlying data:
  - Behavioral Anomalies (anomaly_report.csv, from Milestone 2's Isolation
    Forest pipeline over logon/device logs)
  - Data Access Violations (from datasets/file.csv, real CERT r4.2
    file-access log - file_count/unique_files features added later)
Combined these total 55% of the spec's weight. Weights are NOT renormalized
to 100% - the score is reported on its true 0-0.55 scale so it never implies
coverage the project doesn't have.

There is still no privilege-change log, no separate access-pattern log, and
no historical incident log in this project. Those 3 categories (45% of spec
weight) remain "NOT COMPUTED - no data source" in the output. This is a
deliberate, disclosed limitation, not an oversight.

If/when logs for the remaining categories become available, the WEIGHTS dict
and score calculation below are structured so they can be added without a
rewrite.
"""

import pandas as pd
import numpy as np

INPUT_REPORT = "anomaly_report.csv"
INPUT_FEATURES = "user_daily_features.csv"
OUTPUT_RISK_SCORES = "user_risk_scores.csv"

# Only category with real data right now. Kept as a dict so it's obvious
# how/where to plug in the other 4 categories later.
WEIGHTS = {
    "behavioral_anomalies": 0.35,     # matches spec weight
    "data_access_violations": 0.20,   # matches spec weight - NOW COMPUTED from file.csv
    # "privilege_misuse":        0.25,  # NOT COMPUTED - no privilege log
    # "access_pattern_deviation":0.10,  # NOT COMPUTED - no separate access log
    # "historical_security":     0.10,  # NOT COMPUTED - no incident history log
}
# NOTE: weights sum to 0.55, not 1.00 - deliberately NOT renormalized.
# Score reflects only the 2 categories with real data; max possible score is 55,
# not 100, so it stays literally true to the spec's weighting rather than
# implying full coverage.

RISK_BUCKETS = [
    (0.75, "Critical"),
    (0.50, "High"),
    (0.25, "Medium"),
    (0.00, "Low"),
]


def load_anomalies():
    df = pd.read_csv(INPUT_REPORT, parse_dates=["day"])
    return df


def load_features():
    df = pd.read_csv(INPUT_FEATURES, parse_dates=["day"])
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


def compute_data_access_component(features_df):
    """
    Aggregate per-user file-access activity (file_count, unique_files from
    datasets/file.csv) into a single 0-1 'badness' score for Data Access
    Violations. Uses the same per-user mean-zscore + peak-zscore blend
    pattern as the behavioral anomaly component for consistency.
    """
    agg = features_df.groupby("user").agg(
        mean_file_zscore=("file_count_zscore", "mean"),
        peak_file_zscore=("file_count_zscore", "max"),
        mean_unique_files_zscore=("unique_files_zscore", "mean"),
        peak_unique_files_zscore=("unique_files_zscore", "max"),
    ).reset_index()

    def normalize(s):
        rng = s.max() - s.min()
        if rng == 0:
            return pd.Series(0.0, index=s.index)
        return (s - s.min()) / rng

    file_norm = normalize(agg["mean_file_zscore"])
    peak_file_norm = normalize(agg["peak_file_zscore"])
    unique_norm = normalize(agg["mean_unique_files_zscore"])

    agg["data_access_violations"] = (
        0.4 * file_norm + 0.3 * peak_file_norm + 0.3 * unique_norm
    )

    return agg[["user", "mean_file_zscore", "peak_file_zscore", "data_access_violations"]]


def compute_insider_risk_score(agg):
    agg = agg.copy()
    agg["insider_risk_score"] = (
        agg["behavioral_anomalies"] * WEIGHTS["behavioral_anomalies"]
        + agg["data_access_violations"] * WEIGHTS["data_access_violations"]
    )
    # Score is on a 0-0.55 scale (weights not renormalized - see note above).
    # Convert risk buckets to the same scale so categorization stays meaningful.
    scaled_buckets = [(t * sum(WEIGHTS.values()), label) for t, label in RISK_BUCKETS]

    def bucket(score):
        for threshold, label in scaled_buckets:
            if score >= threshold:
                return label
        return "Low"

    agg["risk_category"] = agg["insider_risk_score"].apply(bucket)

    # Remaining categories still genuinely have no data source - disclosed, not fabricated
    for missing_cat in ["privilege_misuse_indicators",
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

    print("\nLoading daily features (for data access component)...")
    features_df = load_features()

    print("\nComputing behavioral anomaly component...")
    agg = compute_behavioral_anomaly_component(df)

    print("Computing data access violations component (from file.csv)...")
    data_access_agg = compute_data_access_component(features_df)
    agg = pd.merge(agg, data_access_agg, on="user", how="left")
    agg["data_access_violations"] = agg["data_access_violations"].fillna(0)

    print("Computing insider risk scores...")
    agg = compute_insider_risk_score(agg)
    agg = generate_top_reasons(df, agg)

    agg = agg.sort_values("insider_risk_score", ascending=False)

    ordered_cols = [
        "user", "insider_risk_score", "risk_category",
        "anomalous_day_count", "mean_anomaly_score", "worst_anomaly_score",
        "data_access_violations", "mean_file_zscore", "peak_file_zscore",
        "most_common_anomaly_trigger",
        "privilege_misuse_indicators",
        "access_pattern_deviations", "historical_security_events",
    ]
    agg[ordered_cols].to_csv(OUTPUT_RISK_SCORES, index=False)

    print(f"\nSaved: {OUTPUT_RISK_SCORES} ({len(agg)} users)")
    print("\nRisk category breakdown:")
    print(agg["risk_category"].value_counts().to_string())
    print("\nTop 10 highest-risk users:")
    print(agg[ordered_cols[:6]].head(10).to_string(index=False))

    print("\nNOTE: Score reflects Behavioral Anomalies (35%) + Data Access Violations (20%)")
    print("= 55% of spec weight, computed from real data (logon/device logs + file.csv).")
    print("Privilege Misuse, Access Pattern Deviations, and Historical Security Events")
    print("are NOT included - no underlying log data exists for them in this project.")


if __name__ == "__main__":
    main()
