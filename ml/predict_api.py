from fastapi import APIRouter, UploadFile, File, HTTPException
import pandas as pd
import numpy as np
import joblib
import os
import io

router = APIRouter()

MODEL_PATH = os.path.join(os.path.dirname(__file__), "insider_model.pkl")
BASELINES_PATH = os.path.join(os.path.dirname(__file__), "user_baselines.csv")
MANUAL_LOG_PATH = os.path.join(os.path.dirname(__file__), "manual_predictions_log.csv")

FEATURE_COLS = ["logon_count", "logoff_count", "unique_pcs", "after_hours_ratio", "device_connects"]

_model = None
_baselines = None
_global_means = None
_global_stds = None


def _load():
    global _model, _baselines, _global_means, _global_stds
    if _model is None:
        if not os.path.exists(MODEL_PATH) or not os.path.exists(BASELINES_PATH):
            raise HTTPException(status_code=500, detail="Model or baselines not found. Run behavioral_analytics.py first.")
        _model = joblib.load(MODEL_PATH)
        _baselines = pd.read_csv(BASELINES_PATH).set_index("user")
        _global_means = _baselines[[f"{c}_mean" for c in FEATURE_COLS]].mean()
        _global_stds = _baselines[[f"{c}_std" for c in FEATURE_COLS]].mean()


def _risk_category(risk_score: float) -> str:
    if risk_score >= 75:
        return "Critical"
    elif risk_score >= 50:
        return "High"
    elif risk_score >= 25:
        return "Medium"
    else:
        return "Low"


def _log_manual_prediction(result: dict):
    file_exists = os.path.isfile(MANUAL_LOG_PATH)
    row = pd.DataFrame([result])
    row.to_csv(MANUAL_LOG_PATH, mode="a", header=not file_exists, index=False)


def _score_row(row: dict):
    _load()
    user = row.get("user")

    if user in _baselines.index:
        source = "user_baseline"
    else:
        source = "global_fallback"

    feature_vector = [[row.get(c, 0) or 0 for c in FEATURE_COLS]]
    anomaly_score = _model.decision_function(feature_vector)[0]
    is_anomaly = _model.predict(feature_vector)[0]  # -1 anomaly, 1 normal

    # Derived risk score: anomaly_score is roughly centered at 0
    # (negative = anomalous, positive = normal). Mapped to a 0-100 risk scale.
    # This is a direct transform of anomaly_score, not a model-native probability.
    risk_score = max(0.0, min(100.0, (0.5 - anomaly_score) * 100))
    confidence = max(0.0, min(100.0, abs(anomaly_score) * 100 + 50))

    result = {
        "user": user,
        "day": row.get("day"),
        "prediction": "Insider" if is_anomaly == -1 else "Normal",
        "anomaly_score": float(anomaly_score),
        "risk_score": round(float(risk_score), 2),
        "risk_category": _risk_category(risk_score),
        "confidence": round(float(confidence), 2),
        "baseline_source": source,
    }

    if user == "manual_input":
        _log_manual_prediction(result)

    return result


@router.post("/predict")
def predict_csv(file: UploadFile = File(...)):
    content = file.file.read()
    df = pd.read_csv(io.BytesIO(content))

    missing = [c for c in FEATURE_COLS if c not in df.columns]
    if missing:
        raise HTTPException(status_code=400, detail=f"CSV missing required columns: {missing}")

    results = [_score_row(row) for row in df.to_dict(orient="records")]
    return {"count": len(results), "predictions": results}
