from __future__ import annotations

from datetime import datetime
from pathlib import Path
import os

import pandas as pd

DATASET_PATH = Path(os.getenv("CYBERSHEID_DATASET", "threat_detection_52000.csv"))
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
    target = DATASET_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(upload.getvalue())
    df = pd.read_csv(target)
    validate_dataset(df)
    return df, str(target)


def validate_dataset(df: pd.DataFrame) -> list[str]:
    required = set(MODEL_FEATURES) | {"label"}
    missing = sorted(required - set(df.columns))
    if missing:
        raise ValueError("Dataset is missing required columns: " + ", ".join(missing))
    if df.empty:
        raise ValueError("Dataset contains no records.")
    return sorted(set(df.columns) - required)


def find_dataset_path() -> Path:
    candidates = [
        DATASET_PATH,
        Path("data") / DATASET_PATH.name,
        Path("threat_detection_52000.csv"),
        Path("threat_detection_reduced.csv"),
        Path("data") / "threat_detection_52000.csv",
        Path("data") / "threat_detection_reduced.csv",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return DATASET_PATH


def load_dataset() -> pd.DataFrame | None:
    path = find_dataset_path()
    if not path.is_file():
        return None
    try:
        df = pd.read_csv(path)
        validate_dataset(df)
        return df
    except Exception:
        return None


def dataset_status() -> str:
    df = load_dataset()
    if df is None:
        return "No valid dataset found"
    path = find_dataset_path()
    return f"{len(df):,} rows · {df['label'].nunique()} threat classes · {path.name}"


def dataset_distribution(df: pd.DataFrame) -> pd.DataFrame:
    counts = df["label"].fillna("Unknown").value_counts().rename_axis("Threat Category").reset_index(name="Records")
    counts["Share"] = counts["Records"] / counts["Records"].sum()
    return counts
