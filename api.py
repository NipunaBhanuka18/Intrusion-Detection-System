# api.py (Definitive Final Version)

import joblib
import pandas as pd
from fastapi import FastAPI
from pydantic import BaseModel
import numpy as np


# --- 1. Define the input data structure ---
class NetworkData(BaseModel):
    duration: int;
    protocol_type: int;
    service: int;
    flag: int;
    src_bytes: int;
    dst_bytes: int;
    land: int;
    wrong_fragment: int;
    urgent: int;
    hot: int;
    num_failed_logins: int;
    logged_in: int;
    num_compromised: int;
    root_shell: int;
    su_attempted: int;
    num_root: int;
    num_file_creations: int;
    num_shells: int;
    num_access_files: int;
    num_outbound_cmds: int;
    is_host_login: int;
    is_guest_login: int;
    count: int;
    srv_count: int;
    serror_rate: float;
    srv_serror_rate: float;
    rerror_rate: float;
    srv_rerror_rate: float;
    same_srv_rate: float;
    diff_srv_rate: float;
    srv_diff_host_rate: float;
    dst_host_count: int;
    dst_host_srv_count: int;
    dst_host_same_srv_rate: float;
    dst_host_diff_srv_rate: float;
    dst_host_same_src_port_rate: float;
    dst_host_srv_diff_host_rate: float;
    dst_host_serror_rate: float;
    dst_host_srv_serror_rate: float;
    dst_host_rerror_rate: float;
    dst_host_srv_rerror_rate: float


# --- 2. Load trained artifacts ---
# Change this line in api.py
model = joblib.load("models/final_model.joblib")
le = joblib.load("models/label_encoder.joblib")
column_order = joblib.load("models/column_order.joblib")

# --- 3. Create FastAPI app ---
app = FastAPI(title="Intrusion Detection API", version="3.0")

# --- 4. Business logic mapping ---
CONFIDENCE_THRESHOLD = 0.95
LOW_CONF_NORMAL_THRESHOLD = 0.60
ALERT_MAP = {"Normal": "Normal", "DoS": "Critical Alert - High Volume Attack",
             "Probe": "Suspicious - Reconnaissance Activity", "R2L": "Warning - Unauthorized Access Attempt",
             "U2R": "CRITICAL - Privilege Escalation Detected"}


# --- 5. Prediction endpoint with final logic ---
@app.post("/predict", tags=["Prediction"])
def predict(data: NetworkData):
    try:
        # --- HEURISTIC RULE FOR CLASSIC DoS ATTACK ---
        # This is a hard-coded safety net for the model's known blind spot.
        if data.serror_rate == 1.0 and data.srv_serror_rate == 1.0 and data.src_bytes == 0:
            return {
                "status": "Critical Alert - High Volume Attack",
                "predicted_class": "DoS",
                "confidence": 1.0  # We are 100% confident due to the rule
            }

        # --- If not caught by heuristic, proceed with the AI model ---
        input_df = pd.DataFrame([data.model_dump()])
        input_df = input_df[column_order]

        prediction_numeric = model.predict(input_df)
        all_probas = model.predict_proba(input_df)[0]
        confidence = all_probas.max()
        prediction_label = le.inverse_transform(prediction_numeric)[0]
        status = ALERT_MAP.get(prediction_label, "Unknown Anomaly Detected")

        if status != "Normal" and confidence < CONFIDENCE_THRESHOLD:
            status = "Suspicious - Low Confidence Alert"
        elif status == "Normal" and confidence < LOW_CONF_NORMAL_THRESHOLD:
            status = "Suspicious - Low Confidence Normal"

        return {"status": status, "predicted_class": prediction_label, "confidence": float(confidence)}
    except Exception as e:
        return {"error": str(e)}


# --- 6. Health check ---
@app.get("/", tags=["Health Check"])
def read_root():
    return {"status": "API is running - Final Version"}