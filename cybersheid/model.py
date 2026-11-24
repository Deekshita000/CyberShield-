from __future__ import annotations

import os
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

DATASET_FEATURES = [
    "src_ip", "dst_ip", "protocol", "src_port", "dst_port", "packet_count",
    "bytes_sent", "duration_sec", "failed_connections", "login_attempts",
    "connection_rate", "avg_payload_size", "flag_count",
]


def model_path() -> Path:
    return Path(os.getenv("CYBERSHEID_MODEL_PATH", "models/random_forest.joblib"))


def load_model():
    path = model_path()
    if not path.is_file():
        return None, f"No saved model found at {path}."
    try:
        return joblib.load(path), f"Loaded saved model: {path}"
    except Exception as exc:
        return None, f"Could not load model ({type(exc).__name__}): {exc}"


def feature_names(model=None) -> list[str]:
    if model is not None:
        pipeline_feature_names = getattr(model, "feature_names_in_", None)
        if pipeline_feature_names is not None:
            return [str(x) for x in pipeline_feature_names]
        # Inspect a pipeline's preprocessing/feature names when possible.
        try:
            for step_name in ("preprocessor", "features", "columntransformer"):
                step = getattr(model, "named_steps", {}).get(step_name)
                names = getattr(step, "feature_names_in_", None)
                if names is not None:
                    return [str(x) for x in names]
        except Exception:
            pass
    configured = os.getenv("CYBERSHEID_FEATURES")
    if configured:
        return [x.strip() for x in configured.split(",") if x.strip()]
    return DATASET_FEATURES.copy()


def predict(model, values: dict) -> dict:
    names = feature_names(model)
    missing = [name for name in names if name not in values]
    if missing:
        raise ValueError("Missing model fields: " + ", ".join(missing))
    row = pd.DataFrame([[values[name] for name in names]], columns=names)
    prediction = model.predict(row)[0]
    confidence = None
    if hasattr(model, "predict_proba"):
        probabilities = np.asarray(model.predict_proba(row))[0]
        confidence = float(np.max(probabilities))
    label = str(prediction)
    normal = label.strip().lower() in {"0", "normal", "benign", "false", "normal traffic"}
    category = "Normal Traffic" if normal else label
    return {"label": label, "category": category, "confidence": confidence, "normal": normal}
