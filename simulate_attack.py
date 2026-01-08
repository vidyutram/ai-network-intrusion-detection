import requests
import time
from random import uniform, randint

API_URL = "http://127.0.0.1:8000/predict"

# Predefined malicious feature patterns based on NSL-KDD attack behavior
def generate_attack():
    return {
        "duration": uniform(5, 30),
        "protocol_type": "tcp",
        "service": "other",
        "flag": "S0",  # incomplete connection (common in SYN attacks)
        "src_bytes": 0,
        "dst_bytes": 0,
        "land": 0,

        # Fragmentation / packet manipulation
        "wrong_fragment": randint(1, 3),
        "urgent": 0,

        # Suspicious login-related behavior (R2L/U2R attacks)
        "hot": randint(5, 15),
        "num_failed_logins": randint(3, 8),
        "logged_in": 0,
        "num_compromised": randint(5, 20),
        "root_shell": 0,
        "su_attempted": randint(1, 2),
        "num_root": randint(5, 15),
        "num_file_creations": randint(5, 12),
        "num_shells": randint(1, 3),
        "num_access_files": randint(5, 10),
        "num_outbound_cmds": 0,

        "is_host_login": 0,
        "is_guest_login": 0,

        # Traffic count anomalies (DoS/Probe patterns)
        "count": randint(50, 100),
        "srv_count": randint(50, 100),
        "serror_rate": uniform(0.7, 1.0),
        "srv_serror_rate": uniform(0.7, 1.0),
        "rerror_rate": uniform(0.4, 0.9),
        "srv_rerror_rate": uniform(0.4, 0.9),
        "same_srv_rate": uniform(0.0, 0.4),
        "diff_srv_rate": uniform(0.5, 1.0),
        "srv_diff_host_rate": uniform(0.5, 1.0),

        # Host-based anomalies
        "dst_host_count": randint(200, 255),
        "dst_host_srv_count": randint(50, 100),
        "dst_host_same_srv_rate": uniform(0.0, 0.3),
        "dst_host_diff_srv_rate": uniform(0.5, 1.0),
        "dst_host_same_src_port_rate": uniform(0.0, 0.2),
        "dst_host_srv_diff_host_rate": uniform(0.4, 1.0),
        "dst_host_serror_rate": uniform(0.6, 1.0),
        "dst_host_srv_serror_rate": uniform(0.6, 1.0),
        "dst_host_rerror_rate": uniform(0.4, 0.9),
        "dst_host_srv_rerror_rate": uniform(0.4, 0.9),
        "src_ip": "10.0.0.50",
        "dst_ip": "203.0.113.10",  # in our demo threat intel list
        "src_port": 44444,
        "dst_port": 80
    }


def send_attack():
    attack_data = generate_attack()
    print("[*] Sending simulated attack traffic...")
    response = requests.post(API_URL, json=attack_data)

    if response.status_code == 200:
        print(">>> Attack Recorded:", response.json())
    else:
        print("!!! Error:", response.text)


def main():
    print("=== SIMULATED ATTACK GENERATOR ===")
    print("Sending 10 attack samples...")

    for i in range(10):
        send_attack()
        time.sleep(1)

    print("=== Done. Check your dashboard. ===")


if __name__ == "__main__":
    main()
