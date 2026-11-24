from __future__ import annotations

from datetime import datetime
from pathlib import Path
import os

import pandas as pd

DATASET_PATH = Path(os.getenv("CYBERSHEID_DATASET", "data/threat_detection_reduced.csv"))
MODEL_FEATURES = [
    "src_ip", "dst_ip", "protocol", "src_port", "dst_port", "packet_count",
    "bytes_sent", "duration_sec", "failed_connections", "login_attempts",
    "connection_rate", "avg_payload_size", "flag_count",
]
NUMERIC_FEATURES = [
    "src_port", "dst_port", "packet_count", "bytes_sent", "duration_sec",
    "failed_connections", "login_attempts", "connection_rate",
    "avg_payload_size", "flag_count",
]


def save_uploaded_dataset(upload) -> tuple[pd.DataFrame, str]:
    DATASET_PATH.parent.mkdir(parents=True, exist_ok=True)
    bytes_data = upload.getvalue()
    DATASET_PATH.write_bytes(bytes_data)
    df = pd.read_csv(DATASET_PATH)
    validate_dataset(df)
    return df, str(DATASET_PATH)


def validate_dataset(df: pd.DataFrame) -> list[str]:
    required = set(MODEL_FEATURES) | {"label"}
    missing = sorted(required - set(df.columns))
    if missing:
        raise ValueError("Dataset is missing required columns: " + ", ".join(missing))
    return sorted(set(df.columns) - required)


def load_dataset() -> pd.DataFrame | None:
    if not DATASET_PATH.is_file():
        return None
    try:
        df = pd.read_csv(DATASET_PATH)
        validate_dataset(df)
        return df
    except Exception:
        return None


def dataset_status() -> str:
    df = load_dataset()
    if df is None:
        return "No dataset uploaded"
    return f"{len(df):,} rows · {df['label'].nunique()} threat classes"


def dataset_distribution(df: pd.DataFrame) -> pd.DataFrame:
    counts = df["label"].fillna("Unknown").value_counts().rename_axis("Threat Category").reset_index(name="Records")
    counts["Share"] = counts["Records"] / counts["Records"].sum()
    return counts
