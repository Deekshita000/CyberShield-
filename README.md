# CYBERSHEID

A responsive Streamlit cybersecurity threat-analysis dashboard inspired by the attached dark navy reference.

## Run locally

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

The repository includes `threat_detection_52000.csv`. The Reports page loads it automatically and provides real class and record distributions.

## Dataset

The uploaded CSV has 13 input features plus `label`:

- src_ip
- dst_ip
- protocol
- src_port
- dst_port
- packet_count
- bytes_sent
- duration_sec
- failed_connections
- login_attempts
- connection_rate
- avg_payload_size
- flag_count
- label

Set `CYBERSHEID_DATASET` to a custom dataset path if needed.

## Saved Random Forest model

Place an existing trained scikit-learn-compatible artifact at `models/random_forest.joblib`, or set `CYBERSHEID_MODEL_PATH`. The app does not retrain the model. If the saved artifact is a Pipeline with preprocessing and categorical encoders, provide the full Pipeline artifact. The app currently does not fabricate a model if no artifact exists.

No held-out evaluation metrics are claimed without actual test data and supplied model predictions.
