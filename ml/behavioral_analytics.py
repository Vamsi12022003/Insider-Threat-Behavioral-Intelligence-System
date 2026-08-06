"""
Insider Threat Behavioral Intelligence System
Milestone 2: Behavioral Analytics & Anomaly Detection

Covers all 5 milestone tasks:
1. Behavioral profiling engine   -> build_daily_features()
2. Behavioral baselines          -> add_user_baselines()
3. Anomaly detection workflows   -> run_isolation_forest()
4. Threat detection models       -> IsolationForest model itself
5. Anomaly reports                -> generate_anomaly_report()

Also saves the trained model + per-user baselines to disk so a separate
live-prediction endpoint (predict_api.py) can score new incoming rows
without retraining.
"""

import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest

LOGON_PATH = "../datasets/logon.csv"
DEVICE_PATH = "../datasets/device.csv"
OUTPUT_REPORT = "anomaly_report.csv"
OUTPUT_FEATURES = "user_daily_features.csv"
OUTPUT_MODEL = "insider_model.pkl"
OUTPUT_BASELINES = "user_baselines.csv"


def load_data():
    logon = pd.read_csv(LOGON_PATH, parse_dates=["date"])
    device = pd.read_csv(DEVICE_PATH, parse_dates=["date"])
    return logon, device


# ---------------------------------------------------------------------
# TASK 1: Behavioral Profiling Engine
# Turn raw event logs into per-user, per-day behavioral features
# ---------------------------------------------------------------------
def build_daily_features(logon, device):
    logon = logon.copy()
    logon["day"] = logon["date"].dt.date
    logon["hour"] = logon["date"].dt.hour

    # after-hours = before 7am or after 7pm (adjust as needed)
    logon["after_hours"] = ((logon["hour"] < 7) | (logon["hour"] >= 19)).astype(int)

    logon_daily = logon.groupby(["user", "day"]).agg(
        logon_count=("activity", lambda x: (x == "Logon").sum()),
        logoff_count=("activity", lambda x: (x == "Logoff").sum()),
        unique_pcs=("pc", "nunique"),
        after_hours_logons=("after_hours", "sum"),
    ).reset_index()

    logon_daily["after_hours_ratio"] = (
        logon_daily["after_hours_logons"] / logon_daily["logon_count"].replace(0, np.nan)
    ).fillna(0)

    device = device.copy()
    device["day"] = device["date"].dt.date
    device_daily = device.groupby(["user", "day"]).agg(
        device_connects=("activity", lambda x: (x == "Connect").sum()),
    ).reset_index()

    features = pd.merge(logon_daily, device_daily, on=["user", "day"], how="left")
    features["device_connects"] = features["device_connects"].fillna(0)

    return features


# ---------------------------------------------------------------------
# TASK 2: Behavioral Baselines
# Per-user mean/std across their own history -> deviation z-scores
# ---------------------------------------------------------------------
def add_user_baselines(features):
    feature_cols = [
        "logon_count", "logoff_count", "unique_pcs",
        "after_hours_ratio", "device_connects"
    ]

    baselines = features.groupby("user")[feature_cols].agg(["mean", "std"])
    baselines.columns = [f"{col}_{stat}" for col, stat in baselines.columns]
    baselines = baselines.reset_index()

    features = pd.merge(features, baselines, on="user", how="left")

    for col in feature_cols:
        mean_col, std_col = f"{col}_mean", f"{col}_std"
        features[f"{col}_zscore"] = (
            (features[col] - features[mean_col]) / features[std_col].replace(0, np.nan)
        ).fillna(0)

    return features, feature_cols


# ---------------------------------------------------------------------
# TASK 3 & 4: Anomaly Detection Workflow + Threat Detection Model
# Isolation Forest flags behaviorally abnormal user-days
# ---------------------------------------------------------------------
def run_isolation_forest(features, feature_cols, contamination=0.02):
    model_input = features[feature_cols].fillna(0)

    model = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        random_state=42,
    )
    model.fit(model_input)

    features["anomaly_score"] = model.decision_function(model_input)
    features["is_anomaly"] = model.predict(model_input)  # -1 = anomaly, 1 = normal
    features["is_anomaly"] = features["is_anomaly"].map({-1: 1, 1: 0})

    return features, model


# ---------------------------------------------------------------------
# TASK 5: Anomaly Report Generation
# ---------------------------------------------------------------------
def generate_anomaly_report(features, feature_cols):
    anomalies = features[features["is_anomaly"] == 1].copy()

    zscore_cols = [f"{c}_zscore" for c in feature_cols]

    def top_reason(row):
        idx = row[zscore_cols].abs().idxmax()
        feature_name = idx.replace("_zscore", "")
        return f"{feature_name} (z={row[idx]:.2f})"

    anomalies["primary_reason"] = anomalies.apply(top_reason, axis=1)

    report = anomalies[["user", "day", "anomaly_score", "primary_reason"] + feature_cols]
    report = report.sort_values("anomaly_score")  # most negative = most anomalous

    return report


# ---------------------------------------------------------------------
# Save trained model + per-user baselines for live prediction
# (used by ml/predict_api.py so new rows can be scored without retraining)
# ---------------------------------------------------------------------
def save_model_and_baselines(features, model, feature_cols):
    joblib.dump(model, OUTPUT_MODEL)

    baseline_cols = ["user"] + [
        c for c in features.columns if c.endswith("_mean") or c.endswith("_std")
    ]
    baselines_df = features[baseline_cols].drop_duplicates(subset="user")
    baselines_df.to_csv(OUTPUT_BASELINES, index=False)

    return baselines_df


def main():
    print("Loading data...")
    logon, device = load_data()
    print(f"  logon events: {len(logon):,} | device events: {len(device):,}")

    print("\n[Task 1] Building behavioral profiles (daily features per user)...")
    features = build_daily_features(logon, device)
    print(f"  {len(features):,} user-day records created")

    print("\n[Task 2] Computing behavioral baselines & deviations...")
    features, feature_cols = add_user_baselines(features)

    print("\n[Task 3 & 4] Running anomaly detection (Isolation Forest)...")
    features, model = run_isolation_forest(features, feature_cols)
    n_anomalies = features["is_anomaly"].sum()
    print(f"  {n_anomalies:,} anomalous user-days flagged out of {len(features):,} "
          f"({n_anomalies/len(features)*100:.2f}%)")

    print("\n[Task 5] Generating anomaly report...")
    report = generate_anomaly_report(features, feature_cols)
    report.to_csv(OUTPUT_REPORT, index=False)
    features.to_csv(OUTPUT_FEATURES, index=False)

    print(f"\nSaved: {OUTPUT_REPORT} ({len(report)} rows)")
    print(f"Saved: {OUTPUT_FEATURES} ({len(features)} rows)")

    print("\nSaving trained model and per-user baselines for live prediction...")
    baselines_df = save_model_and_baselines(features, model, feature_cols)
    print(f"Saved: {OUTPUT_MODEL}")
    print(f"Saved: {OUTPUT_BASELINES} ({len(baselines_df)} users)")

    print("\nTop 10 most anomalous user-days:")
    print(report.head(10)[["user", "day", "anomaly_score", "primary_reason"]].to_string(index=False))


if __name__ == "__main__":
    main()