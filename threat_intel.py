import os

THREAT_FILE = "threat_intel_ips.txt"

# Load a simple IP blocklist from a text file (one IP per line).
# If file is missing, use a few demo IPs.
def _load_ips():
    ips = set()
    if os.path.exists(THREAT_FILE):
        with open(THREAT_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    ips.add(line)
        print(f"[INFO] Loaded {len(ips)} threat intel IPs from {THREAT_FILE}")
    else:
        # Demo IPs for testing
        ips.update({
            "203.0.113.10",
            "198.51.100.7",
            "192.0.2.66",
        })
        print(f"[WARN] {THREAT_FILE} not found. Using demo malicious IPs: {ips}")
    return ips


_MALICIOUS_IPS = _load_ips()


def is_malicious_ip(ip: str | None) -> bool:
    if not ip:
        return False
    return ip in _MALICIOUS_IPS
