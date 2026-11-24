from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path
import os
import sqlite3
import random

import numpy as np
import pandas as pd

DB_PATH = Path(os.getenv("CYBERSHEID_DB", "data/cybersheid.db"))
SEVERITIES = ["Critical", "High", "Medium", "Low"]
CATEGORIES = ["Malware", "Authentication", "C2 Communication", "Data Loss", "Reconnaissance", "DNS Tunneling"]


def connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with connect() as db:
        db.execute("""CREATE TABLE IF NOT EXISTS detections (
            id INTEGER PRIMARY KEY AUTOINCREMENT, threat TEXT NOT NULL, severity TEXT NOT NULL,
            category TEXT NOT NULL, risk INTEGER NOT NULL, source_ip TEXT NOT NULL,
            status TEXT NOT NULL, detected_at TEXT NOT NULL, origin TEXT NOT NULL,
            confidence REAL, details TEXT
        )""")
        if db.execute("SELECT COUNT(*) FROM detections").fetchone()[0] == 0:
            # Synthetic records for interface preview only; these are not captured traffic.
            now = datetime.now()
            rows = []
            examples = [
                ("Suspicious Login Attempt", "High", "Authentication", 72, "192.168.1.45", "Open"),
                ("Malicious File Detected", "Critical", "Malware", 95, "10.0.0.23", "Open"),
                ("Unusual Outbound Traffic", "Medium", "C2 Communication", 45, "172.16.0.12", "Investigating"),
                ("Brute Force Attempt", "High", "Authentication", 68, "192.168.1.78", "Open"),
                ("Port Scan Detected", "Medium", "Reconnaissance", 38, "10.0.0.56", "Resolved"),
                ("Potential Data Exfiltration", "High", "Data Loss", 73, "192.168.1.32", "Open"),
                ("Suspicious DNS Query", "Medium", "DNS Tunneling", 42, "172.16.0.98", "Investigating"),
                ("Ransomware Behavior", "Critical", "Ransomware", 92, "10.0.0.45", "Open"),
                ("Unusual Login Location", "Low", "Authentication", 24, "192.168.1.19", "Resolved"),
                ("Network Reconnaissance", "Medium", "Reconnaissance", 52, "172.16.0.44", "Resolved"),
                ("Suspicious Archive", "High", "Malware", 79, "10.0.0.78", "Investigating"),
                ("Large Outbound Transfer", "High", "Data Loss", 81, "192.168.1.66", "Open"),
            ]
            for i, item in enumerate(examples):
                rows.append((*item, (now - timedelta(hours=i * 3 + 1)).isoformat(timespec="seconds"), "DEMO", None, "Synthetic demonstration record"))
            db.executemany("INSERT INTO detections (threat,severity,category,risk,source_ip,status,detected_at,origin,confidence,details) VALUES (?,?,?,?,?,?,?,?,?,?)", rows)


def get_detections() -> pd.DataFrame:
    with connect() as db:
        return pd.read_sql_query("SELECT * FROM detections ORDER BY detected_at DESC", db)


def save_detection(threat: str, severity: str, category: str, risk: int, source_ip: str,
                   origin: str, confidence: float | None = None, details: str = "") -> int:
    with connect() as db:
        cur = db.execute("INSERT INTO detections (threat,severity,category,risk,source_ip,status,detected_at,origin,confidence,details) VALUES (?,?,?,?,?,?,?,?,?,?)",
                         (threat, severity, category, int(risk), source_ip, "Open", datetime.now().isoformat(timespec="seconds"), origin, confidence, details))
        return int(cur.lastrowid)


def update_status(detection_id: int, status: str) -> None:
    with connect() as db:
        db.execute("UPDATE detections SET status=? WHERE id=?", (status, detection_id))


def demo_metrics() -> dict:
    # Explicitly illustrative evaluation values; replaced only by supplied evaluation data.
    return {"Accuracy": 96.91, "Precision": 96.93, "Recall": 96.91, "F1 Score": 96.91,
            "True Positive": 9599, "False Negative": 1, "False Positive": 0, "True Negative": 800}


def demo_series(days: int = 7) -> pd.DataFrame:
    rng = np.random.default_rng(12)
    dates = pd.date_range(end=pd.Timestamp.today().normalize(), periods=days)
    return pd.DataFrame({"Date": dates, "Critical": rng.integers(1, 8, days), "High": rng.integers(4, 15, days), "Medium": rng.integers(8, 24, days)})
