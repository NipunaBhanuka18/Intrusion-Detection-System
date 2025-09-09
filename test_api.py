# test_api.py (Final Version)
import pytest
from fastapi.testclient import TestClient
from api import app

client = TestClient(app)

normal_traffic_sample = {"duration": 0, "protocol_type": 1, "service": 24, "flag": 9, "src_bytes": 287, "dst_bytes": 2738, "land": 0, "wrong_fragment": 0, "urgent": 0, "hot": 0, "num_failed_logins": 0, "logged_in": 1, "num_compromised": 0, "root_shell": 0, "su_attempted": 0, "num_root": 0, "num_file_creations": 0, "num_shells": 0, "num_access_files": 0, "num_outbound_cmds": 0, "is_host_login": 0, "is_guest_login": 0, "count": 3, "srv_count": 3, "serror_rate": 0.0, "srv_serror_rate": 0.0, "rerror_rate": 0.0, "srv_rerror_rate": 0.0, "same_srv_rate": 1.0, "diff_srv_rate": 0.0, "srv_diff_host_rate": 0.0, "dst_host_count": 3, "dst_host_srv_count": 3, "dst_host_same_srv_rate": 1.0, "dst_host_diff_srv_rate": 0.0, "dst_host_same_src_port_rate": 0.33, "dst_host_srv_diff_host_rate": 0.0, "dst_host_serror_rate": 0.0, "dst_host_srv_serror_rate": 0.0, "dst_host_rerror_rate": 0.0, "dst_host_srv_rerror_rate": 0.0}
dos_attack_sample = {"duration": 0, "protocol_type": 1, "service": 49, "flag": 5, "src_bytes": 0, "dst_bytes": 0, "land": 0, "wrong_fragment": 0, "urgent": 0, "hot": 0, "num_failed_logins": 0, "logged_in": 0, "num_compromised": 0, "root_shell": 0, "su_attempted": 0, "num_root": 0, "num_file_creations": 0, "num_shells": 0, "num_access_files": 0, "num_outbound_cmds": 0, "is_host_login": 0, "is_guest_login": 0, "count": 248, "srv_count": 18, "serror_rate": 1.0, "srv_serror_rate": 1.0, "rerror_rate": 0.0, "srv_rerror_rate": 0.0, "same_srv_rate": 0.07, "diff_srv_rate": 0.05, "srv_diff_host_rate": 0.0, "dst_host_count": 255, "dst_host_srv_count": 18, "dst_host_same_srv_rate": 0.07, "dst_host_diff_srv_rate": 0.05, "dst_host_same_src_port_rate": 0.0, "dst_host_srv_diff_host_rate": 0.0, "dst_host_serror_rate": 1.0, "dst_host_srv_serror_rate": 1.0, "dst_host_rerror_rate": 0.0, "dst_host_srv_rerror_rate": 0.0}

def test_health_check():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"status": "API is running - Final Version"}

def test_predict_normal():
    response = client.post("/predict", json=normal_traffic_sample)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "Normal"
    assert data["predicted_class"] == "Normal"

def test_predict_dos_attack():
    response = client.post("/predict", json=dos_attack_sample)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "Critical Alert - High Volume Attack"
    assert data["predicted_class"] == "DoS"

def test_bad_data_validation():
    response = client.post("/predict", json={"duration": 0})
    assert response.status_code == 422