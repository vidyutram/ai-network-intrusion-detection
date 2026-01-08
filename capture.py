from scapy.all import sniff, IP, TCP, UDP
from data import FEATURE_NAMES
import threading
import requests

API_URL = "http://127.0.0.1:8000/predict"

def map_service(port: int, proto: str) -> str:
    if proto == "tcp":
        if port in [80, 8080, 443]:
            return "http"
        if port in [21, 20]:
            return "ftp"
        if port == 22:
            return "ssh"
        if port == 25:
            return "smtp"
        if port == 110:
            return "pop_3"
        if port == 53:
            return "domain_u"
    if proto == "udp":
        if port == 53:
            return "domain_u"
    return "other"


def packet_to_features(pkt):
    if IP not in pkt:
        return None

    ip = pkt[IP]
    src_ip = ip.src
    dst_ip = ip.dst

    protocol_type = "tcp"
    dport = 0
    sport = 0
    payload_len = 0

    if TCP in pkt:
        protocol_type = "tcp"
        sport = int(pkt[TCP].sport)
        dport = int(pkt[TCP].dport)
        payload_len = len(bytes(pkt[TCP].payload))
    elif UDP in pkt:
        protocol_type = "udp"
        sport = int(pkt[UDP].sport)
        dport = int(pkt[UDP].dport)
        payload_len = len(bytes(pkt[UDP].payload))
    else:
        protocol_type = "icmp"

    service = map_service(dport, protocol_type)
    flag = "SF"

    feats = {f: 0 for f in FEATURE_NAMES}

    feats["duration"] = 0.0
    feats["protocol_type"] = protocol_type
    feats["service"] = service
    feats["flag"] = flag
    feats["src_bytes"] = float(payload_len)
    feats["dst_bytes"] = 0.0
    feats["land"] = 1 if ip.src == ip.dst else 0

    # Attach extra fields (not part of FEATURE_NAMES but used by server)
    feats["src_ip"] = src_ip
    feats["dst_ip"] = dst_ip
    feats["src_port"] = int(sport)
    feats["dst_port"] = int(dport)

    return feats


def send_to_api(features):
    try:
        resp = requests.post(API_URL, json=features, timeout=2)
        if resp.status_code != 200:
            print("[WARN] API status:", resp.status_code, resp.text)
        else:
            data = resp.json()
            print(
                f"[EVENT] {data.get('prediction')} "
                f"prob={data.get('attack_probability')} "
                f"proto={data.get('protocol_type')} svc={data.get('service')}"
            )
    except Exception as e:
        print("[ERROR] Failed to send to API:", e)


def process_packet(pkt):
    feats = packet_to_features(pkt)
    if feats is None:
        return
    threading.Thread(target=send_to_api, args=(feats,), daemon=True).start()

def main():
    print("=== Live Packet Capture for NIDS Demo ===")
    print("NOTE: You may need to run this script with sudo/administrator privileges.")
    print(f"Sending extracted features to {API_URL}")
    print("Press Ctrl+C to stop.\n")

    # You can specify iface='eth0' or similar if needed
    sniff(
        prn=process_packet,
        store=False
        # filter="ip"  # you can add BPF filter if you like
    )


if __name__ == "__main__":
    main()
