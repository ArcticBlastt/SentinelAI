import pickle
import joblib
import numpy as np
import pandas as pd
import logging
import threading
import time
from datetime import datetime

from flask import Flask, jsonify, render_template_string, request
from scapy.all import AsyncSniffer, IP, TCP, UDP


# ============================================================
# CONFIGURATION
# ============================================================

RF_MODEL_PATH = "random_forest_model.pkl"
IF_MODEL_PATH = "isolation_forest_model.pkl"

LOG_FILE = "ids_alerts.log"

FLOW_TIMEOUT = 5
CHECK_INTERVAL = 1
MIN_PACKETS_FOR_JUDGEMENT = 5

ANOMALY_THRESHOLD = -0.75   # see report: CICIDS2017 vs live-traffic domain shift
RECENT_THREAT_WINDOW = 30   # seconds — how long "ACTIVE THREAT" stays lit after an alert

# Port-scan heuristic: many distinct destination ports from one source IP in
# a short window is a behavioral pattern that no single flow's features can
# capture on their own (a single unanswered SYN is indistinguishable from a
# normal failed connection). So this runs alongside the ML models, not instead of them.
SCAN_WINDOW_SECONDS = 10
SCAN_PORT_THRESHOLD = 15

MAX_EVENTS = 300


logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format="%(asctime)s - %(message)s")


FEATURE_COLUMNS = [
    "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Fwd Packet Length Max",
    "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean",
    "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean",
    "Flow IAT Std", "Flow IAT Max", "Flow IAT Min", "Fwd IAT Total", "Fwd IAT Mean",
    "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min", "Bwd IAT Total", "Bwd IAT Mean",
    "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min", "Fwd PSH Flags", "Bwd PSH Flags",
    "Fwd URG Flags", "Bwd URG Flags", "Fwd Header Length", "Bwd Header Length",
    "Fwd Packets/s", "Bwd Packets/s", "Min Packet Length", "Max Packet Length",
    "Packet Length Mean", "Packet Length Std", "Packet Length Variance",
    "FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count",
    "ACK Flag Count", "URG Flag Count", "CWE Flag Count", "ECE Flag Count",
    "Down/Up Ratio", "Average Packet Size", "Avg Fwd Segment Size", "Avg Bwd Segment Size",
    "Fwd Header Length.1", "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate", "Subflow Fwd Packets",
    "Subflow Fwd Bytes", "Subflow Bwd Packets", "Subflow Bwd Bytes", "Init_Win_bytes_forward",
    "Init_Win_bytes_backward", "act_data_pkt_fwd", "min_seg_size_forward", "Active Mean",
    "Active Std", "Active Max", "Active Min", "Idle Mean", "Idle Std", "Idle Max", "Idle Min"
]


# ============================================================
# LOAD MODELS
# ============================================================

print("\nLoading models...")

rf_model = joblib.load(RF_MODEL_PATH)
print(f"✓ Random Forest loaded ({rf_model.n_features_in_} features expected)")

if_model = joblib.load(IF_MODEL_PATH)
print(f"✓ Isolation Forest loaded ({if_model.n_features_in_} features expected)")


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def safe_mean(values): return float(np.mean(values)) if values else 0
def safe_std(values): return float(np.std(values, ddof=1)) if len(values) > 1 else 0
def safe_max(values): return float(max(values)) if values else 0
def safe_min(values): return float(min(values)) if values else 0
def safe_variance(values): return float(np.var(values, ddof=1)) if len(values) > 1 else 0

def calculate_iats(timestamps):
    if len(timestamps) <= 1:
        return []
    return [(timestamps[i] - timestamps[i - 1]) * 1000000 for i in range(1, len(timestamps))]


def get_packet_endpoints(packet):
    if not packet.haslayer(IP):
        return None

    ip_layer = packet[IP]
    src_ip, dst_ip = ip_layer.src, ip_layer.dst

    if packet.haslayer(TCP):
        protocol = 6
        src_port, dst_port = packet[TCP].sport, packet[TCP].dport
    elif packet.haslayer(UDP):
        protocol = 17
        src_port, dst_port = packet[UDP].sport, packet[UDP].dport
    else:
        return None

    return (src_ip, src_port, dst_ip, dst_port, protocol)


def create_canonical_flow_key(src_ip, src_port, dst_ip, dst_port, protocol):
    ordered = tuple(sorted([(src_ip, src_port), (dst_ip, dst_port)]))
    return (ordered[0], ordered[1], protocol)


def determine_flow_direction(packets):
    first_packet = packets[0]
    endpoints = get_packet_endpoints(first_packet)
    if endpoints is None:
        return None

    first_src_ip, first_src_port = endpoints[0], endpoints[1]

    for packet in packets:
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            flags = int(tcp.flags)
            if (flags & 0x02) and not (flags & 0x10):
                return (packet[IP].src, tcp.sport)

    return (first_src_ip, first_src_port)


def extract_features(packets):
    if not packets:
        return None

    forward_endpoint = determine_flow_direction(packets)
    if forward_endpoint is None:
        return None

    forward_ip, forward_port = forward_endpoint

    forward_packets, backward_packets = [], []

    for packet in packets:
        endpoints = get_packet_endpoints(packet)
        if endpoints is None:
            continue
        src_ip, src_port = endpoints[0], endpoints[1]
        (forward_packets if (src_ip == forward_ip and src_port == forward_port) else backward_packets).append(packet)

    if not forward_packets:
        return None

    first_forward = forward_packets[0]
    endpoints = get_packet_endpoints(first_forward)
    destination_ip, destination_port = endpoints[2], endpoints[3]

    all_timestamps = sorted([float(p.time) for p in packets])
    fwd_timestamps = sorted([float(p.time) for p in forward_packets])
    bwd_timestamps = sorted([float(p.time) for p in backward_packets])

    flow_duration = (all_timestamps[-1] - all_timestamps[0]) * 1000000 if len(all_timestamps) > 1 else 0

    packet_lengths = [len(p) for p in packets]
    fwd_lengths = [len(p) for p in forward_packets]
    bwd_lengths = [len(p) for p in backward_packets]

    total_fwd_packets, total_bwd_packets = len(forward_packets), len(backward_packets)
    total_fwd_bytes, total_bwd_bytes = sum(fwd_lengths), sum(bwd_lengths)
    total_packets, total_bytes = total_fwd_packets + total_bwd_packets, total_fwd_bytes + total_bwd_bytes

    flow_iats = calculate_iats(all_timestamps)
    fwd_iats = calculate_iats(fwd_timestamps)
    bwd_iats = calculate_iats(bwd_timestamps)

    if flow_duration > 0:
        duration_seconds = flow_duration / 1000000
        flow_bytes_per_second = total_bytes / duration_seconds
        flow_packets_per_second = total_packets / duration_seconds
        fwd_packets_per_second = total_fwd_packets / duration_seconds
        bwd_packets_per_second = total_bwd_packets / duration_seconds
    else:
        flow_bytes_per_second = flow_packets_per_second = 0
        fwd_packets_per_second = bwd_packets_per_second = 0

    fin_count = syn_count = rst_count = psh_count = 0
    ack_count = urg_count = cwe_count = ece_count = 0
    fwd_psh = bwd_psh = fwd_urg = bwd_urg = 0
    fwd_header_length = bwd_header_length = 0
    init_win_forward = init_win_backward = 0
    act_data_pkt_fwd = 0

    for packet in forward_packets:
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            flags = int(tcp.flags)
            if flags & 0x01: fin_count += 1
            if flags & 0x02: syn_count += 1
            if flags & 0x04: rst_count += 1
            if flags & 0x08: psh_count += 1; fwd_psh += 1
            if flags & 0x10: ack_count += 1
            if flags & 0x20: urg_count += 1; fwd_urg += 1
            if flags & 0x80: cwe_count += 1
            if flags & 0x40: ece_count += 1
            fwd_header_length += (tcp.dataofs or 5) * 4
            if init_win_forward == 0: init_win_forward = tcp.window
            if len(tcp.payload) > 0: act_data_pkt_fwd += 1
        elif packet.haslayer(UDP):
            fwd_header_length += 8

    for packet in backward_packets:
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            flags = int(tcp.flags)
            if flags & 0x01: fin_count += 1
            if flags & 0x02: syn_count += 1
            if flags & 0x04: rst_count += 1
            if flags & 0x08: psh_count += 1; bwd_psh += 1
            if flags & 0x10: ack_count += 1
            if flags & 0x20: urg_count += 1; bwd_urg += 1
            if flags & 0x80: cwe_count += 1
            if flags & 0x40: ece_count += 1
            bwd_header_length += (tcp.dataofs or 5) * 4
            if init_win_backward == 0: init_win_backward = tcp.window
        elif packet.haslayer(UDP):
            bwd_header_length += 8

    down_up_ratio = total_bwd_packets / total_fwd_packets if total_fwd_packets > 0 else 0
    min_seg_size_forward = min(fwd_lengths) if fwd_lengths else 0
    active_values = [flow_duration] if flow_duration > 0 else []
    idle_values = []

    features = {
        "Destination Port": destination_port, "Flow Duration": flow_duration,
        "Total Fwd Packets": total_fwd_packets, "Total Backward Packets": total_bwd_packets,
        "Total Length of Fwd Packets": total_fwd_bytes, "Total Length of Bwd Packets": total_bwd_bytes,
        "Fwd Packet Length Max": safe_max(fwd_lengths), "Fwd Packet Length Min": safe_min(fwd_lengths),
        "Fwd Packet Length Mean": safe_mean(fwd_lengths), "Fwd Packet Length Std": safe_std(fwd_lengths),
        "Bwd Packet Length Max": safe_max(bwd_lengths), "Bwd Packet Length Min": safe_min(bwd_lengths),
        "Bwd Packet Length Mean": safe_mean(bwd_lengths), "Bwd Packet Length Std": safe_std(bwd_lengths),
        "Flow Bytes/s": flow_bytes_per_second, "Flow Packets/s": flow_packets_per_second,
        "Flow IAT Mean": safe_mean(flow_iats), "Flow IAT Std": safe_std(flow_iats),
        "Flow IAT Max": safe_max(flow_iats), "Flow IAT Min": safe_min(flow_iats),
        "Fwd IAT Total": sum(fwd_iats), "Fwd IAT Mean": safe_mean(fwd_iats),
        "Fwd IAT Std": safe_std(fwd_iats), "Fwd IAT Max": safe_max(fwd_iats), "Fwd IAT Min": safe_min(fwd_iats),
        "Bwd IAT Total": sum(bwd_iats), "Bwd IAT Mean": safe_mean(bwd_iats),
        "Bwd IAT Std": safe_std(bwd_iats), "Bwd IAT Max": safe_max(bwd_iats), "Bwd IAT Min": safe_min(bwd_iats),
        "Fwd PSH Flags": fwd_psh, "Bwd PSH Flags": bwd_psh, "Fwd URG Flags": fwd_urg, "Bwd URG Flags": bwd_urg,
        "Fwd Header Length": fwd_header_length, "Bwd Header Length": bwd_header_length,
        "Fwd Packets/s": fwd_packets_per_second, "Bwd Packets/s": bwd_packets_per_second,
        "Min Packet Length": safe_min(packet_lengths), "Max Packet Length": safe_max(packet_lengths),
        "Packet Length Mean": safe_mean(packet_lengths), "Packet Length Std": safe_std(packet_lengths),
        "Packet Length Variance": safe_variance(packet_lengths),
        "FIN Flag Count": fin_count, "SYN Flag Count": syn_count, "RST Flag Count": rst_count,
        "PSH Flag Count": psh_count, "ACK Flag Count": ack_count, "URG Flag Count": urg_count,
        "CWE Flag Count": cwe_count, "ECE Flag Count": ece_count,
        "Down/Up Ratio": down_up_ratio, "Average Packet Size": safe_mean(packet_lengths),
        "Avg Fwd Segment Size": safe_mean(fwd_lengths), "Avg Bwd Segment Size": safe_mean(bwd_lengths),
        "Fwd Header Length.1": fwd_header_length,
        "Fwd Avg Bytes/Bulk": 0, "Fwd Avg Packets/Bulk": 0, "Fwd Avg Bulk Rate": 0,
        "Bwd Avg Bytes/Bulk": 0, "Bwd Avg Packets/Bulk": 0, "Bwd Avg Bulk Rate": 0,
        "Subflow Fwd Packets": total_fwd_packets, "Subflow Fwd Bytes": total_fwd_bytes,
        "Subflow Bwd Packets": total_bwd_packets, "Subflow Bwd Bytes": total_bwd_bytes,
        "Init_Win_bytes_forward": init_win_forward, "Init_Win_bytes_backward": init_win_backward,
        "act_data_pkt_fwd": act_data_pkt_fwd, "min_seg_size_forward": min_seg_size_forward,
        "Active Mean": safe_mean(active_values), "Active Std": safe_std(active_values),
        "Active Max": safe_max(active_values), "Active Min": safe_min(active_values),
        "Idle Mean": safe_mean(idle_values), "Idle Std": safe_std(idle_values),
        "Idle Max": safe_max(idle_values), "Idle Min": safe_min(idle_values)
    }

    return (features, (forward_ip, forward_port, destination_ip, destination_port))


def build_dataframe(features, model):
    X_live = pd.DataFrame([[features.get(f, 0) for f in FEATURE_COLUMNS]], columns=FEATURE_COLUMNS)
    X_live = X_live.replace([np.inf, -np.inf], np.nan).fillna(0)

    if hasattr(model, "feature_names_in_"):
        expected_names = list(model.feature_names_in_)
        stripped_to_expected = {name.strip(): name for name in expected_names}
        rename_map = {col: stripped_to_expected[col.strip()] for col in X_live.columns if col.strip() in stripped_to_expected}
        X_live = X_live.rename(columns=rename_map)
        X_live = X_live[expected_names]

    return X_live


# ============================================================
# SHARED STATE (dashboard + engine control)
# ============================================================

state_lock = threading.Lock()

engine_state = {
    "running": False,
    "sniffer": None,
    "stop_event": None,
    "monitor_thread": None,
    "started_at": None
}

dashboard_state = {
    "stats": {"total": 0, "attacks": 0, "zero_day": 0, "normal": 0, "skipped": 0},
    "events": [],
    "current": {"verdict": "IDLE", "detail": "Scan not started", "flow": "", "time": None},
    "last_alert_time": 0
}

active_flows = {}
last_seen = {}
flows_lock = threading.Lock()

# source_ip -> list of (timestamp, destination_port) seen recently
scan_tracker = {}
scan_tracker_lock = threading.Lock()
flagged_scanners = {}   # source_ip -> time already alerted, to avoid spamming


def check_port_scan(source_ip, destination_port):
    """Returns True the first time a source IP crosses the distinct-port
    threshold within the time window. Won't re-fire again for a while."""

    now = time.time()

    with scan_tracker_lock:
        entries = scan_tracker.setdefault(source_ip, [])
        entries.append((now, destination_port))

        # drop anything outside the window
        cutoff = now - SCAN_WINDOW_SECONDS
        entries[:] = [(ts, p) for (ts, p) in entries if ts >= cutoff]

        distinct_ports = len(set(p for (ts, p) in entries))

        if distinct_ports >= SCAN_PORT_THRESHOLD:
            last_flag = flagged_scanners.get(source_ip, 0)
            if now - last_flag > SCAN_WINDOW_SECONDS:
                flagged_scanners[source_ip] = now
                return distinct_ports

    return None


def push_event(event_type, flow_label, detail):
    now = time.time()

    with state_lock:
        dashboard_state["stats"]["total"] += 1
        dashboard_state["stats"][event_type] += 1

        dashboard_state["current"] = {
            "verdict": event_type,
            "detail": detail,
            "flow": flow_label,
            "time": datetime.now().strftime("%H:%M:%S")
        }

        if event_type in ("attacks", "zero_day"):
            dashboard_state["last_alert_time"] = now

        dashboard_state["events"].insert(0, {
            "time": datetime.now().strftime("%H:%M:%S"),
            "type": event_type,
            "flow": flow_label,
            "detail": detail
        })
        dashboard_state["events"] = dashboard_state["events"][:MAX_EVENTS]


# ============================================================
# CLASSIFICATION
# ============================================================

def packet_handler(packet):
    endpoints = get_packet_endpoints(packet)
    if endpoints is None:
        return

    src_ip, src_port, dst_ip, dst_port, protocol = endpoints
    flow_key = create_canonical_flow_key(src_ip, src_port, dst_ip, dst_port, protocol)

    with flows_lock:
        active_flows.setdefault(flow_key, []).append(packet)
        last_seen[flow_key] = time.time()


def classify_flow(features, flow_info):
    forward_ip, forward_port, destination_ip, destination_port = flow_info
    flow_label = f"{forward_ip}:{forward_port} -> {destination_ip}:{destination_port}"

    total_packets = features.get("Total Fwd Packets", 0) + features.get("Total Backward Packets", 0)

    # ----------------------------------------------------
    # HEURISTIC: PORT SCAN BEHAVIOR (across flows, not per-flow)
    # ----------------------------------------------------

    scan_hits = check_port_scan(forward_ip, destination_port)
    if scan_hits:
        detail = f"Port Scan Detected — {scan_hits} distinct ports probed within {SCAN_WINDOW_SECONDS}s from {forward_ip}"
        logging.info(f"[ATTACK] {flow_label} | {detail}")
        push_event("attacks", flow_label, detail)
        return

    X_rf = build_dataframe(features, rf_model)

    if X_rf.shape[1] != rf_model.n_features_in_:
        push_event("skipped", flow_label, "Feature mismatch")
        return

    # RF always runs, even on short flows — scans (e.g. Nmap SYN scan) are
    # often only 1-2 packets per flow, which is exactly the pattern we need
    # to catch, not filter out.
    rf_prediction = rf_model.predict(X_rf)[0]

    confidence = None
    if hasattr(rf_model, "predict_proba"):
        probabilities = rf_model.predict_proba(X_rf)[0]
        confidence = max(probabilities) * 100

    is_benign = str(rf_prediction).upper() == "BENIGN"

    # The Isolation Forest (zero-day) check needs enough packets to be
    # statistically meaningful, so it's the only thing gated by packet count.
    zero_day_flag = False
    anomaly_score = None
    insufficient_for_zero_day = total_packets < MIN_PACKETS_FOR_JUDGEMENT

    if is_benign and not insufficient_for_zero_day:
        X_if = build_dataframe(features, if_model)
        anomaly_score = if_model.score_samples(X_if)[0]
        if anomaly_score < ANOMALY_THRESHOLD:
            zero_day_flag = True

    if not is_benign:
        detail = f"Type: {rf_prediction}"
        if confidence is not None:
            detail += f" | Confidence: {confidence:.2f}%"
        logging.info(f"[ATTACK] {flow_label} | {detail}")
        push_event("attacks", flow_label, detail)

    elif zero_day_flag:
        detail = f"Anomaly score = {anomaly_score:.4f} (threshold: {ANOMALY_THRESHOLD})"
        logging.info(f"[ZERO-DAY] {flow_label} | {detail}")
        push_event("zero_day", flow_label, detail)

    else:
        if insufficient_for_zero_day:
            detail = f"{total_packets} packets — too few for zero-day check"
        else:
            detail = f"score: {anomaly_score:.4f}"
        push_event("normal", flow_label, detail)


def flow_monitor(stop_event):
    while not stop_event.is_set():
        time.sleep(CHECK_INTERVAL)
        now = time.time()
        expired_keys = []

        with flows_lock:
            for flow_key, ts in list(last_seen.items()):
                if now - ts > FLOW_TIMEOUT:
                    expired_keys.append(flow_key)

        for flow_key in expired_keys:
            with flows_lock:
                flow_packets = active_flows.pop(flow_key, None)
                last_seen.pop(flow_key, None)

            if flow_packets:
                result = extract_features(flow_packets)
                if result:
                    features, flow_info = result
                    classify_flow(features, flow_info)


# ============================================================
# ENGINE CONTROL
# ============================================================

def start_engine():
    with state_lock:
        if engine_state["running"]:
            return False

        stop_event = threading.Event()
        monitor_thread = threading.Thread(target=flow_monitor, args=(stop_event,), daemon=True)
        monitor_thread.start()

        sniffer = AsyncSniffer(filter="tcp or udp", prn=packet_handler, store=False)
        sniffer.start()

        engine_state.update({
            "running": True,
            "sniffer": sniffer,
            "stop_event": stop_event,
            "monitor_thread": monitor_thread,
            "started_at": time.time()
        })

        dashboard_state["current"] = {"verdict": "normal", "detail": "Scan started", "flow": "", "time": datetime.now().strftime("%H:%M:%S")}

    return True


def stop_engine():
    with state_lock:
        if not engine_state["running"]:
            return False

        engine_state["sniffer"].stop()
        engine_state["stop_event"].set()
        engine_state["running"] = False
        engine_state["started_at"] = None

    # flush any flows still open
    with flows_lock:
        remaining = list(active_flows.items())
        active_flows.clear()
        last_seen.clear()

    for flow_key, flow_packets in remaining:
        result = extract_features(flow_packets)
        if result:
            features, flow_info = result
            classify_flow(features, flow_info)

    with state_lock:
        dashboard_state["current"] = {"verdict": "IDLE", "detail": "Scan stopped", "flow": "", "time": datetime.now().strftime("%H:%M:%S")}

    return True


# ============================================================
# FLASK APP
# ============================================================

app = Flask(__name__)

HTML_PAGE = """
<!DOCTYPE html>
<html>
<head>
<title>SOC Live IDS Dashboard</title>
<meta charset="utf-8">
<style>
  :root {
    --bg: #0b0e14; --panel: #131722; --border: #232838;
    --text: #e6e9ef; --muted: #8b93a7;
    --attack: #ff4d5e; --zeroday: #ffb020; --normal: #2ecc71; --skipped: #4a5169;
  }
  * { box-sizing: border-box; }
  body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; margin: 0; padding: 28px; }
  h1 { font-size: 20px; font-weight: 600; margin: 0; }
  .top-row { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
  .controls button {
    border: none; border-radius: 8px; padding: 10px 20px; font-size: 13px; font-weight: 600;
    cursor: pointer; margin-left: 10px;
  }
  #btn-start { background: var(--normal); color: #06280f; }
  #btn-stop { background: var(--attack); color: #2b0006; }
  button:disabled { opacity: 0.35; cursor: not-allowed; }

  .status-banner {
    padding: 20px 24px; border-radius: 12px; margin-bottom: 20px;
    display: flex; justify-content: space-between; align-items: center;
    border: 1px solid var(--border); transition: background 0.3s ease;
  }
  .status-banner .verdict { font-size: 20px; font-weight: 700; }
  .status-banner .detail { color: var(--muted); font-size: 13px; margin-top: 4px; }
  .status-banner.idle { background: #131722; }
  .status-banner.normal { background: rgba(46,204,113,0.12); }
  .status-banner.attacks { background: rgba(255,77,94,0.15); }
  .status-banner.zero_day { background: rgba(255,176,32,0.15); }
  .status-banner.skipped { background: #131722; }
  .status-banner .verdict.idle { color: var(--muted); }
  .status-banner .verdict.normal { color: var(--normal); }
  .status-banner .verdict.attacks { color: var(--attack); }
  .status-banner .verdict.zero_day { color: var(--zeroday); }
  .status-banner .verdict.skipped { color: var(--skipped); }

  .threat-pill {
    font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.04em;
    padding: 6px 14px; border-radius: 999px;
  }
  .threat-pill.clear { background: rgba(46,204,113,0.15); color: var(--normal); }
  .threat-pill.active { background: rgba(255,77,94,0.2); color: var(--attack); animation: pulse 1.2s infinite; }
  @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.5; } }

  .stats { display: grid; grid-template-columns: repeat(5, 1fr); gap: 14px; margin-bottom: 20px; }
  .stat-card { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 16px; }
  .stat-value { font-size: 24px; font-weight: 700; }
  .stat-label { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; margin-top: 4px; }
  .stat-card.attacks .stat-value { color: var(--attack); }
  .stat-card.zero_day .stat-value { color: var(--zeroday); }
  .stat-card.normal .stat-value { color: var(--normal); }
  .stat-card.skipped .stat-value { color: var(--skipped); }

  .section-title { font-size: 13px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; margin: 24px 0 10px; }

  table { width: 100%; border-collapse: collapse; background: var(--panel); border: 1px solid var(--border); border-radius: 10px; overflow: hidden; }
  th, td { text-align: left; padding: 10px 14px; font-size: 13px; border-bottom: 1px solid var(--border); }
  th { color: var(--muted); text-transform: uppercase; font-size: 11px; letter-spacing: 0.05em; }
  tr:last-child td { border-bottom: none; }

  .badge { display: inline-block; padding: 2px 8px; border-radius: 6px; font-size: 11px; font-weight: 600; text-transform: uppercase; }
  .badge.attacks { background: rgba(255,77,94,0.15); color: var(--attack); }
  .badge.zero_day { background: rgba(255,176,32,0.15); color: var(--zeroday); }
  .badge.normal { background: rgba(46,204,113,0.15); color: var(--normal); }
  .badge.skipped { background: rgba(74,81,105,0.25); color: var(--muted); }

  .empty { color: var(--muted); padding: 20px; text-align: center; }
</style>
</head>
<body>

  <div class="top-row">
    <div>
      <h1>SOC Live IDS Dashboard</h1>
      <div style="color: var(--muted); font-size: 12px; margin-top: 2px;">Random Forest + Isolation Forest</div>
    </div>
    <div class="controls">
      <span id="threat-pill" class="threat-pill clear">All Clear</span>
      <button id="btn-start" onclick="startScan()">▶ Start Scan</button>
      <button id="btn-stop" onclick="stopScan()" disabled>■ Stop Scan</button>
    </div>
  </div>

  <div class="status-banner idle" id="status-banner">
    <div>
      <div class="verdict idle" id="status-verdict">IDLE</div>
      <div class="detail" id="status-detail">Scan not started</div>
    </div>
    <div style="text-align:right; color: var(--muted); font-size: 12px;">
      <div id="status-flow"></div>
      <div id="status-time"></div>
    </div>
  </div>

  <div class="stats">
    <div class="stat-card"><div class="stat-value" id="stat-total">0</div><div class="stat-label">Total Flows</div></div>
    <div class="stat-card attacks"><div class="stat-value" id="stat-attacks">0</div><div class="stat-label">Attacks</div></div>
    <div class="stat-card zero_day"><div class="stat-value" id="stat-zero_day">0</div><div class="stat-label">Possible Zero-Day</div></div>
    <div class="stat-card normal"><div class="stat-value" id="stat-normal">0</div><div class="stat-label">Normal</div></div>
    <div class="stat-card skipped"><div class="stat-value" id="stat-skipped">0</div><div class="stat-label">Skipped</div></div>
  </div>

  <div class="section-title">Alerts (Attacks &amp; Zero-Day only)</div>
  <table>
    <thead><tr><th style="width:90px">Time</th><th style="width:110px">Verdict</th><th>Flow</th><th>Detail</th></tr></thead>
    <tbody id="alerts-body"><tr><td colspan="4" class="empty">No alerts yet</td></tr></tbody>
  </table>

  <div class="section-title">Full Activity Log</div>
  <table>
    <thead><tr><th style="width:90px">Time</th><th style="width:110px">Verdict</th><th>Flow</th><th>Detail</th></tr></thead>
    <tbody id="events-body"><tr><td colspan="4" class="empty">Waiting for flows...</td></tr></tbody>
  </table>

<script>
let scanning = false;

function verdictLabel(v) {
  return v === 'zero_day' ? 'zero-day' : v;
}

async function startScan() {
  await fetch('/api/start', { method: 'POST' });
  refresh();
}

async function stopScan() {
  await fetch('/api/stop', { method: 'POST' });
  refresh();
}

function renderRows(elId, events, emptyText) {
  const tbody = document.getElementById(elId);
  if (events.length === 0) {
    tbody.innerHTML = `<tr><td colspan="4" class="empty">${emptyText}</td></tr>`;
    return;
  }
  tbody.innerHTML = events.map(e => `
    <tr>
      <td>${e.time}</td>
      <td><span class="badge ${e.type}">${verdictLabel(e.type)}</span></td>
      <td>${e.flow}</td>
      <td>${e.detail}</td>
    </tr>
  `).join('');
}

async function refresh() {
  try {
    const res = await fetch('/api/data');
    const data = await res.json();

    scanning = data.running;
    document.getElementById('btn-start').disabled = scanning;
    document.getElementById('btn-stop').disabled = !scanning;

    document.getElementById('stat-total').textContent = data.stats.total;
    document.getElementById('stat-attacks').textContent = data.stats.attacks;
    document.getElementById('stat-zero_day').textContent = data.stats.zero_day;
    document.getElementById('stat-normal').textContent = data.stats.normal;
    document.getElementById('stat-skipped').textContent = data.stats.skipped;

    const banner = document.getElementById('status-banner');
    const verdict = data.current.verdict;
    banner.className = 'status-banner ' + verdict;
    document.getElementById('status-verdict').className = 'verdict ' + verdict;
    document.getElementById('status-verdict').textContent = verdictLabel(verdict).toUpperCase();
    document.getElementById('status-detail').textContent = data.current.detail || '';
    document.getElementById('status-flow').textContent = data.current.flow || '';
    document.getElementById('status-time').textContent = data.current.time || '';

    const pill = document.getElementById('threat-pill');
    if (data.threat_active) {
      pill.className = 'threat-pill active';
      pill.textContent = 'Active Threat';
    } else {
      pill.className = 'threat-pill clear';
      pill.textContent = 'All Clear';
    }

    const alertEvents = data.events.filter(e => e.type === 'attacks' || e.type === 'zero_day');
    renderRows('alerts-body', alertEvents, 'No alerts yet');
    renderRows('events-body', data.events, 'Waiting for flows...');

  } catch (err) {
    console.error('Failed to refresh dashboard', err);
  }
}

refresh();
setInterval(refresh, 2000);
</script>

</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(HTML_PAGE)


@app.route("/api/data")
def api_data():
    with state_lock:
        threat_active = (time.time() - dashboard_state["last_alert_time"]) < RECENT_THREAT_WINDOW if dashboard_state["last_alert_time"] else False
        payload = {
            "stats": dashboard_state["stats"],
            "events": dashboard_state["events"],
            "current": dashboard_state["current"],
            "running": engine_state["running"],
            "threat_active": threat_active
        }
    return jsonify(payload)


@app.route("/api/start", methods=["POST"])
def api_start():
    started = start_engine()
    return jsonify({"started": started})


@app.route("/api/stop", methods=["POST"])
def api_stop():
    stopped = stop_engine()
    return jsonify({"stopped": stopped})


if __name__ == "__main__":
    app.run(debug=False, port=5000)