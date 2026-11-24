from __future__ import annotations

import os
from pathlib import Path
import joblib
import numpy as np
import pandas as pd

# A CICIDS-inspired 13-field example schema. Configure CYBERSHEID_FEATURES to match
# the exact feature order used by your saved artifact when it lacks feature_names_in_.
DEFAULT_FEATURES = [
    "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Fwd Packet Length Max",
    "Bwd Packet Length Max", "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean",
    "Flow IAT Std", "SYN Flag Count",
]


def model_path() -> Path:
    return Path(os.getenv("CYBERSHEID_MODEL_PATH", "models/random_forest.joblib"))


def load_model():
    path = model_path()
    if not path.is_file():
        return None, f"No saved model found at {path}. Add your existing artifact or set CYBERSHEID_MODEL_PATH."
    try:
        return joblib.load(path), f"Loaded saved model: {path}"
    except Exception as exc:
        return None, f"Could not load model ({type(exc).__name__}): {exc}"


def feature_names(model=None) -> list[str]:
    if model is not None and hasattr(model, "feature_names_in_"):
        return [str(x) for x in model.feature_names_in_]
    configured = os.getenv("CYBERSHEID_FEATURES")
    if configured:
        return [x.strip() for x in configured.split(",") if x.strip()]
    return DEFAULT_FEATURES


def predict(model, values: dict[str, float]) -> dict:
    names = feature_names(model)
    if len(values) != len(names) or set(values) != set(names):
        raise ValueError(f"Model expects these {len(names)} fields, in order: {', '.join(names)}")
    row = pd.DataFrame([[float(values[name]) for name in names]], columns=names)
    prediction = model.predict(row)[0]
    confidence = None
    if hasattr(model, "predict_proba"):
        probabilities = np.asarray(model.predict_proba(row))[0]
        confidence = float(np.max(probabilities))
    label = str(prediction)
    category = "Normal Traffic" if label.lower() in {"0", "normal", "benign", "false"} else label
    return {"label": label, "category": category, "confidence": confidence}
