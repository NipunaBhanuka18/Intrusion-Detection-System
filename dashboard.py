# dashboard.py (Final, Smarter Version)

import streamlit as st
import requests
import json
import pandas as pd

# --- Page Configuration ---
st.set_page_config(page_title="Intrusion Detection System", page_icon="🛡️", layout="wide")

# --- API Endpoint ---
API_URL = "http://127.0.0.1:8000/predict"

# --- Data Samples (to use as intelligent defaults) ---
normal_traffic_sample = {"duration": 0, "protocol_type": 1, "service": 24, "flag": 9, "src_bytes": 287,
                         "dst_bytes": 2738, "land": 0, "wrong_fragment": 0, "urgent": 0, "hot": 0,
                         "num_failed_logins": 0, "logged_in": 1, "num_compromised": 0, "root_shell": 0,
                         "su_attempted": 0, "num_root": 0, "num_file_creations": 0, "num_shells": 0,
                         "num_access_files": 0, "num_outbound_cmds": 0, "is_host_login": 0, "is_guest_login": 0,
                         "count": 3, "srv_count": 3, "serror_rate": 0.0, "srv_serror_rate": 0.0, "rerror_rate": 0.0,
                         "srv_rerror_rate": 0.0, "same_srv_rate": 1.0, "diff_srv_rate": 0.0, "srv_diff_host_rate": 0.0,
                         "dst_host_count": 3, "dst_host_srv_count": 3, "dst_host_same_srv_rate": 1.0,
                         "dst_host_diff_srv_rate": 0.0, "dst_host_same_src_port_rate": 0.33,
                         "dst_host_srv_diff_host_rate": 0.0, "dst_host_serror_rate": 0.0,
                         "dst_host_srv_serror_rate": 0.0, "dst_host_rerror_rate": 0.0, "dst_host_srv_rerror_rate": 0.0}
dos_attack_sample = {"duration": 0, "protocol_type": 1, "service": 49, "flag": 5, "src_bytes": 0, "dst_bytes": 0,
                     "land": 0, "wrong_fragment": 0, "urgent": 0, "hot": 0, "num_failed_logins": 0, "logged_in": 0,
                     "num_compromised": 0, "root_shell": 0, "su_attempted": 0, "num_root": 0, "num_file_creations": 0,
                     "num_shells": 0, "num_access_files": 0, "num_outbound_cmds": 0, "is_host_login": 0,
                     "is_guest_login": 0, "count": 248, "srv_count": 18, "serror_rate": 1.0, "srv_serror_rate": 1.0,
                     "rerror_rate": 0.0, "srv_rerror_rate": 0.0, "same_srv_rate": 0.07, "diff_srv_rate": 0.05,
                     "srv_diff_host_rate": 0.0, "dst_host_count": 255, "dst_host_srv_count": 18,
                     "dst_host_same_srv_rate": 0.07, "dst_host_diff_srv_rate": 0.05, "dst_host_same_src_port_rate": 0.0,
                     "dst_host_srv_diff_host_rate": 0.0, "dst_host_serror_rate": 1.0, "dst_host_srv_serror_rate": 1.0,
                     "dst_host_rerror_rate": 0.0, "dst_host_srv_rerror_rate": 0.0}

# --- Page Title ---
st.title("🛡️ Real-Time Intrusion Detection System")
st.write("Enter network traffic features to predict the attack category.")

# --- Sidebar for User Input ---
st.sidebar.header("Input Features")
duration = st.sidebar.number_input("Duration", min_value=0, value=0)
src_bytes = st.sidebar.number_input("Source Bytes", min_value=0, value=250)
dst_bytes = st.sidebar.number_input("Destination Bytes", min_value=0, value=2000)
count = st.sidebar.number_input("Count", min_value=0, value=5)
serror_rate = st.sidebar.slider("Server Error Rate", 0.0, 1.0, 0.0)
logged_in = st.sidebar.selectbox("Logged In", [0, 1], index=1)

# --- Prediction Button ---
if st.sidebar.button("Detect Intrusion"):
    # --- SMART PAYLOAD LOGIC ---
    # If the inputs look like a DoS attack, use the DoS sample as the base.
    # Otherwise, use the Normal sample as the base.
    if serror_rate > 0.9:
        base_payload = dos_attack_sample.copy()
    else:
        base_payload = normal_traffic_sample.copy()

    # Update the base payload with the user's inputs from the sidebar
    payload = base_payload
    payload["duration"] = duration
    payload["src_bytes"] = src_bytes
    payload["dst_bytes"] = dst_bytes
    payload["count"] = count
    payload["serror_rate"] = serror_rate
    payload["logged_in"] = logged_in

    # Send request to the API
    try:
        response = requests.post(API_URL, data=json.dumps(payload))
        response.raise_for_status()
        result = response.json()

        # --- Display Results ---
        st.subheader("Prediction Result")
        status = result.get("status", "N/A")
        predicted_class = result.get("predicted_class", "N/A")
        confidence = result.get("confidence", 0.0)

        if "Normal" in status:
            st.success(f"**Status:** {status}")
        elif "Suspicious" in status or "Warning" in status:
            st.warning(f"**Status:** {status}")
        else:  # Critical Alert
            st.error(f"**Status:** {status}")

        st.write(f"**Predicted Attack Type:** {predicted_class}")
        st.write(f"**Confidence:** {confidence:.4f}")

    except requests.exceptions.RequestException as e:
        st.error(f"API Connection Error: Could not connect. Please ensure the API is running at {API_URL}.")