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

Place an existing trained scikit-learn-compatible artifact at `models/random_forest.joblib`, or upload it in Settings. You can also set `CYBERSHEID_MODEL_PATH`. The app does not retrain the model.

For categorical fields, upload the complete preprocessing pipeline (for example a `Pipeline` containing encoders plus `RandomForestClassifier`). A plain numeric Random Forest should expose `feature_names_in_` or be configured with `CYBERSHEID_FEATURES`.

No held-out evaluation metrics are claimed without actual test data and supplied model predictions.
