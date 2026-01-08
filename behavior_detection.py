import time
from collections import deque, defaultdict
from typing import List, Dict, Any

# Keep recent events in a time window (seconds)
WINDOW_SECONDS = 30
MAX_STORED_EVENTS = 5000

# Heuristic thresholds
VERTICAL_SCAN_PORT_THRESHOLD = 20   # many ports on one host
HORIZONTAL_SCAN_HOST_THRESHOLD = 20 # many hosts on one port
DOS_CONNECTION_THRESHOLD = 50       # many hits to same dst in window

# Each entry: (timestamp, src_ip, dst_ip, dst_port)
_events = deque()


def _cleanup(now: float):
    # Remove old events outside the window
    while _events and (now - _events[0][0]) > WINDOW_SECONDS:
        _events.popleft()
    if len(_events) > MAX_STORED_EVENTS:
        for _ in range(len(_events) - MAX_STORED_EVENTS):
            _events.popleft()


def register_event(src_ip: str | None, dst_ip: str | None, dst_port: int | None) -> List[str]:
    """
    Called for each new connection.
    Returns a list of behavioral alerts (strings) if any heuristics are triggered.
    """
    alerts: List[str] = []
    if not src_ip or dst_port is None:
        return alerts

    now = time.time()
    _events.append((now, src_ip, dst_ip or "", int(dst_port)))
    _cleanup(now)

    # Build views for this source IP
    ports_for_src = set()
    hosts_for_src = set()
    count_per_dst = defaultdict(int)

    for ts, s_ip, d_ip, d_port in _events:
        if s_ip == src_ip:
            ports_for_src.add(d_port)
            hosts_for_src.add(d_ip)
            if d_ip:
                count_per_dst[d_ip] += 1

    # Vertical scan: many ports on a single source
    if len(ports_for_src) >= VERTICAL_SCAN_PORT_THRESHOLD:
        alerts.append(f"Vertical port scan suspected from {src_ip} (ports: {len(ports_for_src)})")

    # Horizontal scan: many hosts from a single source
    if len(hosts_for_src) >= HORIZONTAL_SCAN_HOST_THRESHOLD:
        alerts.append(f"Horizontal port scan suspected from {src_ip} (hosts: {len(hosts_for_src)})")

    # DoS-like: too many hits to same dst host from same src
    for d_ip, count in count_per_dst.items():
        if count >= DOS_CONNECTION_THRESHOLD:
            alerts.append(f"Possible DoS from {src_ip} targeting {d_ip} ({count} hits in {WINDOW_SECONDS}s)")

    return alerts
