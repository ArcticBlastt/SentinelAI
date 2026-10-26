import pickle
import joblib
import numpy as np
import pandas as pd
import logging
import threading
import time
import sqlite3
import sys
import os
import json
from datetime import datetime

from flask import Flask, jsonify, render_template_string, request
from scapy.all import AsyncSniffer, IP, TCP, UDP

import incident_engine


def resource_path(relative_path):
    """Get correct path to a bundled file, both in dev and inside a PyInstaller exe"""
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)


# ============================================================
# CONFIGURATION
# ============================================================

RF_MODEL_PATH = resource_path("random_forest_model.pkl")
IF_MODEL_PATH = resource_path("isolation_forest_model.pkl")

DB_PATH = "sentinelai_history.db"


# ============================================================
# MITRE ATT&CK MAPPING
# ============================================================
# Maps CICIDS2017 attack labels (what the RF model outputs) to real
# MITRE ATT&CK techniques, with a severity level for triage.

MITRE_MAP = {
    "DDoS":                  {"id": "T1498", "name": "Network Denial of Service", "severity": "Critical"},
    "DoS Hulk":               {"id": "T1498", "name": "Network Denial of Service", "severity": "High"},
    "DoS GoldenEye":          {"id": "T1498", "name": "Network Denial of Service", "severity": "High"},
    "DoS slowloris":          {"id": "T1499", "name": "Endpoint Denial of Service", "severity": "High"},
    "DoS Slowhttptest":       {"id": "T1499", "name": "Endpoint Denial of Service", "severity": "High"},
    "Heartbleed":             {"id": "T1212", "name": "Exploitation for Credential Access", "severity": "Critical"},
    "PortScan":               {"id": "T1046", "name": "Network Service Discovery", "severity": "Medium"},
    "Bot":                    {"id": "T1071", "name": "Application Layer Protocol (C2)", "severity": "Critical"},
    "Infiltration":           {"id": "T1190", "name": "Exploit Public-Facing Application", "severity": "Critical"},
    "Web Attack – Brute Force":     {"id": "T1110", "name": "Brute Force", "severity": "High"},
    "Web Attack – XSS":             {"id": "T1059", "name": "Command and Scripting Injection (XSS)", "severity": "Medium"},
    "Web Attack – Sql Injection":   {"id": "T1190", "name": "Exploit Public-Facing Application (SQLi)", "severity": "High"},
    "FTP-Patator":            {"id": "T1110", "name": "Brute Force", "severity": "High"},
    "SSH-Patator":            {"id": "T1110", "name": "Brute Force", "severity": "High"},
}

DEFAULT_ATTACK_MITRE = {"id": "T1046", "name": "Reconnaissance / Unclassified", "severity": "Medium"}
ZERO_DAY_MITRE = {"id": "TA0043", "name": "Unclassified Anomalous Behavior", "severity": "Medium"}
PORT_SCAN_MITRE = MITRE_MAP["PortScan"]


def get_mitre_info(rf_label):
    return MITRE_MAP.get(str(rf_label), DEFAULT_ATTACK_MITRE)


# ============================================================
# HISTORICAL LOGGING (SQLite)
# ============================================================

db_lock = threading.Lock()


def init_db():
    with db_lock:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                epoch REAL NOT NULL,
                type TEXT NOT NULL,
                flow TEXT NOT NULL,
                source_ip TEXT,
                detail TEXT,
                severity TEXT,
                mitre_id TEXT,
                mitre_name TEXT
            )
        """)
        conn.commit()
        conn.close()


def log_event_to_db(event_type, flow_label, detail, source_ip, mitre_info=None):
    severity = mitre_info["severity"] if mitre_info else ("Info" if event_type == "normal" else "Low")
    mitre_id = mitre_info["id"] if mitre_info else None
    mitre_name = mitre_info["name"] if mitre_info else None

    with db_lock:
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "INSERT INTO events (timestamp, epoch, type, flow, source_ip, detail, severity, mitre_id, mitre_name) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                time.time(),
                event_type,
                flow_label,
                source_ip,
                detail,
                severity,
                mitre_id,
                mitre_name
            )
        )
        conn.commit()
        conn.close()


init_db()

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
    "current": {"verdict": "IDLE", "detail": "Scan not started", "flow": "", "time": None, "attack_type": None},
    "last_alert_time": 0,
    "last_attack": None   # snapshot of the most recent attack/zero_day "current", kept on
                           # display while a threat is still active so interleaved normal
                           # flows don't flicker the status banner back to "Normal"
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


def push_event(event_type, flow_label, detail, mitre_info=None, attack_type=None):
    now = time.time()
    source_ip = flow_label.split(":")[0] if ":" in flow_label else flow_label

    with state_lock:
        dashboard_state["stats"]["total"] += 1
        dashboard_state["stats"][event_type] += 1

        dashboard_state["current"] = {
            "verdict": event_type,
            "detail": detail,
            "flow": flow_label,
            "time": datetime.now().strftime("%H:%M:%S"),
            "attack_type": attack_type,
            "mitre_id": mitre_info["id"] if mitre_info else None,
            "mitre_name": mitre_info["name"] if mitre_info else None,
            "severity": mitre_info["severity"] if mitre_info else None
        }

        if event_type in ("attacks", "zero_day"):
            dashboard_state["last_alert_time"] = now
            dashboard_state["last_attack"] = dict(dashboard_state["current"])

        dashboard_state["events"].insert(0, {
            "time": datetime.now().strftime("%H:%M:%S"),
            "type": event_type,
            "flow": flow_label,
            "detail": detail,
            "attack_type": attack_type,
            "mitre_id": mitre_info["id"] if mitre_info else None,
            "mitre_name": mitre_info["name"] if mitre_info else None,
            "severity": mitre_info["severity"] if mitre_info else None
        })
        dashboard_state["events"] = dashboard_state["events"][:MAX_EVENTS]

    log_event_to_db(event_type, flow_label, detail, source_ip, mitre_info)

    # ----------------------------------------------------
    # INCIDENT ENGINE HOOK
    # Every attack/zero-day verdict becomes a tracked incident and
    # kicks off an async AI investigation. Detection logic above this
    # point is untouched — the incident engine is a pure consumer.
    # ----------------------------------------------------
    if event_type in ("attacks", "zero_day"):
        incident_id = incident_engine.create_incident(
            event_type=event_type,
            flow_label=flow_label,
            detail=detail,
            source_ip=source_ip,
            attack_type=attack_type,
            mitre_id=mitre_info["id"] if mitre_info else None,
            mitre_name=mitre_info["name"] if mitre_info else None,
            severity=mitre_info["severity"] if mitre_info else None
        )
        incident_engine.investigate_incident_async(incident_id)


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
        push_event("attacks", flow_label, detail, PORT_SCAN_MITRE, attack_type="Port Scan")
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
        mitre_info = get_mitre_info(rf_prediction)
        detail = f"Type: {rf_prediction} | MITRE {mitre_info['id']}: {mitre_info['name']}"
        if confidence is not None:
            detail += f" | Confidence: {confidence:.2f}%"
        logging.info(f"[ATTACK] {flow_label} | {detail}")
        push_event("attacks", flow_label, detail, mitre_info, attack_type=str(rf_prediction))

    elif zero_day_flag:
        detail = f"Anomaly score = {anomaly_score:.4f} (threshold: {ANOMALY_THRESHOLD})"
        logging.info(f"[ZERO-DAY] {flow_label} | {detail}")
        push_event("zero_day", flow_label, detail, ZERO_DAY_MITRE)

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
<title>SentinelAI — Live SOC Dashboard</title>
<meta charset="utf-8">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@500&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #0a0d14; --panel: #12151f; --panel-hover: #161a26; --border: #232838;
    --text: #e8ebf2; --muted: #8b93a7;
    --accent: #5b8cff; --accent-glow: rgba(91,140,255,0.35);
    --attack: #ff4d5e; --zeroday: #ffb020; --normal: #2ecc71; --skipped: #4a5169;
  }
  * { box-sizing: border-box; }
  html { scrollbar-color: var(--border) var(--bg); }
  body {
    background:
      radial-gradient(900px 500px at 15% -10%, rgba(91,140,255,0.08), transparent),
      radial-gradient(700px 400px at 100% 0%, rgba(255,77,94,0.05), transparent),
      var(--bg);
    color: var(--text); font-family: 'Inter', 'Segoe UI', system-ui, sans-serif;
    margin: 0; padding: 32px 40px 56px; max-width: 1360px; margin-inline: auto;
  }
  ::selection { background: var(--accent-glow); }

  .brand { display: flex; align-items: center; gap: 12px; }
  .brand-mark {
    width: 38px; height: 38px; border-radius: 10px; flex-shrink: 0;
    background: linear-gradient(145deg, var(--accent), #8a5cff);
    display: flex; align-items: center; justify-content: center;
    font-size: 19px; box-shadow: 0 0 22px var(--accent-glow);
  }
  h1 {
    font-size: 22px; font-weight: 800; margin: 0; letter-spacing: -0.01em;
    background: linear-gradient(90deg, #ffffff, #b9c4e0);
    -webkit-background-clip: text; background-clip: text; color: transparent;
  }
  .tagline { color: var(--muted); font-size: 12.5px; margin-top: 2px; letter-spacing: 0.01em; }

  .top-row { display: flex; justify-content: space-between; align-items: center; margin-bottom: 22px; }
  .controls { display: flex; align-items: center; gap: 10px; }
  .controls button {
    border: none; border-radius: 9px; padding: 10px 18px; font-size: 13px; font-weight: 700;
    cursor: pointer; transition: transform 0.12s ease, box-shadow 0.12s ease, opacity 0.12s ease;
  }
  .controls button:hover:not(:disabled) { transform: translateY(-1px); }
  #btn-start { background: var(--normal); color: #06280f; box-shadow: 0 4px 16px rgba(46,204,113,0.25); }
  #btn-stop { background: var(--attack); color: #2b0006; box-shadow: 0 4px 16px rgba(255,77,94,0.2); }
  #btn-clear { background: var(--panel); color: var(--muted); border: 1px solid var(--border) !important; }
  #btn-clear:hover:not(:disabled) { color: var(--text); border-color: #3a4160 !important; }
  button:disabled { opacity: 0.3; cursor: not-allowed; transform: none !important; box-shadow: none !important; }

  .status-banner {
    padding: 22px 26px; border-radius: 14px; margin-bottom: 22px;
    display: flex; justify-content: space-between; align-items: center;
    border: 1px solid var(--border); border-left: 4px solid var(--border);
    transition: background 0.35s ease, border-color 0.35s ease, box-shadow 0.35s ease;
  }
  .status-banner .verdict { font-size: 20px; font-weight: 700; letter-spacing: 0.01em; }
  .status-banner .attack-name {
    font-size: 32px; font-weight: 800; color: var(--attack);
    margin-top: 6px; letter-spacing: 0.01em;
  }
  .status-banner .detail { color: var(--muted); font-size: 13px; margin-top: 6px; }
  .status-banner.idle { background: var(--panel); border-left-color: var(--border); }
  .status-banner.normal { background: rgba(46,204,113,0.1); border-left-color: var(--normal); }
  .status-banner.attacks { background: rgba(255,77,94,0.13); border-left-color: var(--attack); box-shadow: 0 0 30px rgba(255,77,94,0.1); }
  .status-banner.zero_day { background: rgba(255,176,32,0.13); border-left-color: var(--zeroday); box-shadow: 0 0 30px rgba(255,176,32,0.08); }
  .status-banner.skipped { background: var(--panel); border-left-color: var(--skipped); }
  .status-banner .verdict.idle { color: var(--muted); }
  .status-banner .verdict.normal { color: var(--normal); }
  .status-banner .verdict.attacks { color: var(--attack); }
  .status-banner .verdict.zero_day { color: var(--zeroday); }
  .status-banner .verdict.skipped { color: var(--skipped); }

  .threat-pill {
    font-size: 11.5px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em;
    padding: 7px 15px; border-radius: 999px; border: 1px solid transparent;
  }
  .threat-pill.clear { background: rgba(46,204,113,0.12); color: var(--normal); border-color: rgba(46,204,113,0.25); }
  .threat-pill.active { background: rgba(255,77,94,0.18); color: var(--attack); border-color: rgba(255,77,94,0.35); animation: pulse 1.2s infinite; }
  @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.55; } }

  .stats { display: grid; grid-template-columns: repeat(5, 1fr); gap: 14px; margin-bottom: 22px; }
  .stat-card {
    background: var(--panel); border: 1px solid var(--border); border-top: 2px solid var(--border);
    border-radius: 12px; padding: 17px 18px;
    transition: transform 0.15s ease, border-color 0.15s ease, background 0.15s ease;
  }
  .stat-card:hover { transform: translateY(-2px); background: var(--panel-hover); }
  .stat-value { font-size: 25px; font-weight: 800; letter-spacing: -0.01em; }
  .stat-label { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em; margin-top: 5px; }
  .stat-card.attacks { border-top-color: var(--attack); }
  .stat-card.attacks .stat-value { color: var(--attack); }
  .stat-card.zero_day { border-top-color: var(--zeroday); }
  .stat-card.zero_day .stat-value { color: var(--zeroday); }
  .stat-card.normal { border-top-color: var(--normal); }
  .stat-card.normal .stat-value { color: var(--normal); }
  .stat-card.skipped .stat-value { color: var(--skipped); }

  .section-title {
    font-size: 12.5px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.07em;
    margin: 28px 0 10px; display: flex; align-items: center; gap: 8px;
  }
  .section-title::before { content: ""; width: 3px; height: 13px; background: var(--accent); border-radius: 2px; display: inline-block; }

  table { width: 100%; border-collapse: collapse; background: var(--panel); border: 1px solid var(--border); border-radius: 12px; overflow: hidden; }
  th, td { text-align: left; padding: 11px 14px; font-size: 13px; border-bottom: 1px solid var(--border); }
  th { color: var(--muted); text-transform: uppercase; font-size: 10.5px; letter-spacing: 0.06em; background: rgba(255,255,255,0.015); }
  tbody tr { transition: background 0.1s ease; }
  tbody tr:hover { background: rgba(255,255,255,0.025); }
  tr:last-child td { border-bottom: none; }

  .badge { display: inline-block; padding: 2px 8px; border-radius: 6px; font-size: 11px; font-weight: 600; text-transform: uppercase; }
  .badge.attacks { background: rgba(255,77,94,0.15); color: var(--attack); }
  .badge.zero_day { background: rgba(255,176,32,0.15); color: var(--zeroday); }
  .badge.normal { background: rgba(46,204,113,0.15); color: var(--normal); }
  .badge.skipped { background: rgba(74,81,105,0.25); color: var(--muted); }

  .sev { font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 6px; text-transform: uppercase; }
  .sev.Critical { background: rgba(255,20,60,0.2); color: #ff143c; }
  .sev.High { background: rgba(255,77,94,0.15); color: var(--attack); }
  .sev.Medium { background: rgba(255,176,32,0.15); color: var(--zeroday); }
  .sev.Low { background: rgba(74,81,105,0.25); color: var(--muted); }
  .mitre-tag { color: var(--muted); font-size: 11px; margin-left: 6px; }

  .history-grid { display: grid; grid-template-columns: 2fr 1fr; gap: 16px; margin-top: 10px; }
  .history-panel { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 18px; }
  .history-panel h3 { font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; margin: 0 0 14px; }

  .trend-chart { display: flex; align-items: flex-end; gap: 3px; height: 120px; }
  .trend-bar { flex: 1; background: linear-gradient(to top, var(--attack), #ff8a94); border-radius: 3px 3px 0 0; min-height: 2px; position: relative; }
  .trend-bar:hover::after {
    content: attr(data-count); position: absolute; top: -20px; left: 50%; transform: translateX(-50%);
    background: #000; color: #fff; padding: 2px 6px; border-radius: 4px; font-size: 10px; white-space: nowrap;
  }
  .trend-labels { display: flex; justify-content: space-between; margin-top: 6px; font-size: 10px; color: var(--muted); }

  .ip-row { display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid var(--border); font-size: 13px; }
  .ip-row:last-child { border-bottom: none; }
  .ip-count { color: var(--attack); font-weight: 700; }

  .empty { color: var(--muted); padding: 20px; text-align: center; }

  /* -------------------- INCIDENTS -------------------- */
  .incident-row { cursor: pointer; }
  .incident-row:hover { background: rgba(255,255,255,0.03); }

  .status-pill {
    font-size: 11px; font-weight: 700; padding: 3px 10px; border-radius: 999px;
    text-transform: uppercase; letter-spacing: 0.03em; display: inline-block;
  }
  .status-pill.NEW { background: rgba(74,81,105,0.3); color: var(--muted); }
  .status-pill.INVESTIGATING { background: rgba(255,176,32,0.15); color: var(--zeroday); animation: pulse 1.4s infinite; }
  .status-pill.CLASSIFIED { background: rgba(168,85,247,0.15); color: #a855f7; }
  .status-pill.RESPONSE_RECOMMENDED { background: rgba(255,77,94,0.15); color: var(--attack); }
  .status-pill.CONTAINED { background: rgba(46,204,113,0.15); color: var(--normal); }
  .status-pill.CLOSED { background: rgba(74,81,105,0.25); color: var(--muted); }

  .modal-overlay {
    display: none; position: fixed; inset: 0; background: rgba(5,7,12,0.72);
    backdrop-filter: blur(3px); -webkit-backdrop-filter: blur(3px);
    z-index: 100; align-items: flex-start; justify-content: center; padding: 40px 20px;
    overflow-y: auto;
  }
  .modal-overlay.open { display: flex; }
  .modal-box {
    background: var(--panel); border: 1px solid var(--border); border-radius: 16px;
    max-width: 760px; width: 100%; padding: 28px; position: relative;
    box-shadow: 0 20px 60px rgba(0,0,0,0.5);
  }
  .modal-close {
    position: absolute; top: 18px; right: 20px; background: none; border: none;
    color: var(--muted); font-size: 20px; cursor: pointer;
  }
  .modal-title { font-size: 20px; font-weight: 700; margin-bottom: 4px; }
  .modal-subtitle { color: var(--muted); font-size: 13px; margin-bottom: 20px; }

  .modal-section { margin-top: 20px; }
  .modal-section h4 {
    font-size: 11px; color: var(--muted); text-transform: uppercase;
    letter-spacing: 0.05em; margin: 0 0 8px;
  }
  .modal-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-bottom: 4px; }
  .modal-stat { background: rgba(255,255,255,0.03); border-radius: 8px; padding: 10px 12px; }
  .modal-stat .label { font-size: 10px; color: var(--muted); text-transform: uppercase; }
  .modal-stat .value { font-size: 15px; font-weight: 700; margin-top: 2px; }

  .timeline-item {
    display: flex; gap: 12px; padding: 8px 0; border-bottom: 1px solid var(--border); font-size: 13px;
  }
  .timeline-item:last-child { border-bottom: none; }
  .timeline-time { color: var(--muted); min-width: 70px; flex-shrink: 0; }

  .evidence-item {
    background: rgba(255,255,255,0.02); border: 1px solid var(--border); border-radius: 8px;
    padding: 10px 12px; margin-bottom: 8px; font-size: 12px;
  }
  .evidence-tool { color: var(--scan, #a855f7); font-weight: 700; margin-bottom: 4px; }
  .evidence-result { color: var(--muted); white-space: pre-wrap; word-break: break-word; max-height: 120px; overflow-y: auto; }

  .assessment-box {
    background: rgba(255,255,255,0.03); border-left: 3px solid var(--attack);
    padding: 12px 14px; border-radius: 6px; font-size: 13px; line-height: 1.5;
  }

  .action-row { display: flex; gap: 10px; margin-top: 20px; }
  .btn-approve, .btn-reject {
    flex: 1; padding: 10px; border: none; border-radius: 8px; font-weight: 700;
    font-size: 13px; cursor: pointer; text-transform: uppercase;
  }
  .btn-approve { background: var(--normal); color: #06280f; }
  .btn-reject { background: var(--attack); color: #2b0006; }
  .btn-approve:disabled, .btn-reject:disabled { opacity: 0.35; cursor: not-allowed; }

  .decision-note { font-size: 12px; color: var(--muted); margin-top: 10px; text-align: center; }
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
      <button id="btn-clear" onclick="clearDashboard()">🗑 Clear</button>
    </div>
  </div>

  <div class="status-banner idle" id="status-banner">
    <div>
      <div class="verdict idle" id="status-verdict">IDLE</div>
      <div class="attack-name" id="attack-name" style="display:none;"></div>
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
    <thead><tr><th style="width:90px">Time</th><th style="width:100px">Verdict</th><th style="width:120px">Attack Type</th><th style="width:90px">Severity</th><th>Flow</th><th>Detail</th></tr></thead>
    <tbody id="alerts-body"><tr><td colspan="6" class="empty">No alerts yet</td></tr></tbody>
  </table>

  <div class="section-title">Incidents (AI-Investigated)</div>
  <table>
    <thead><tr><th style="width:90px">ID</th><th style="width:140px">Status</th><th style="width:90px">Severity</th><th style="width:140px">MITRE</th><th>Source IP</th><th style="width:90px">Created</th></tr></thead>
    <tbody id="incidents-body"><tr><td colspan="6" class="empty">No incidents yet</td></tr></tbody>
  </table>

  <div class="section-title">History &amp; Trends (last 6 hours)</div>
  <div class="history-grid">
    <div class="history-panel">
      <h3>Attacks Over Time</h3>
      <div class="trend-chart" id="trend-chart"></div>
      <div class="trend-labels" id="trend-labels"></div>
    </div>
    <div class="history-panel">
      <h3>Top Attacker IPs</h3>
      <div id="top-ips"><div class="empty">No data yet</div></div>
    </div>
  </div>

  <div class="section-title">Full Activity Log</div>
  <table>
    <thead><tr><th style="width:90px">Time</th><th style="width:100px">Verdict</th><th style="width:120px">Attack Type</th><th style="width:90px">Severity</th><th>Flow</th><th>Detail</th></tr></thead>
    <tbody id="events-body"><tr><td colspan="6" class="empty">Waiting for flows...</td></tr></tbody>
  </table>

  <div class="modal-overlay" id="incident-modal">
    <div class="modal-box">
      <button class="modal-close" onclick="closeIncidentModal()">&times;</button>
      <div class="modal-title" id="modal-title">INC-000</div>
      <div class="modal-subtitle" id="modal-subtitle"></div>

      <div class="modal-grid">
        <div class="modal-stat"><div class="label">Status</div><div class="value" id="modal-status">—</div></div>
        <div class="modal-stat"><div class="label">Severity</div><div class="value" id="modal-severity">—</div></div>
        <div class="modal-stat"><div class="label">Confidence</div><div class="value" id="modal-confidence">—</div></div>
      </div>

      <div class="modal-section">
        <h4>MITRE ATT&amp;CK</h4>
        <div id="modal-mitre">—</div>
      </div>

      <div class="modal-section">
        <h4>AI Assessment</h4>
        <div class="assessment-box" id="modal-assessment">No assessment yet.</div>
      </div>

      <div class="modal-section">
        <h4>Timeline</h4>
        <div id="modal-timeline"><div class="empty">No timeline yet.</div></div>
      </div>

      <div class="modal-section">
        <h4>Evidence Collected (tool calls)</h4>
        <div id="modal-evidence"><div class="empty">No evidence yet.</div></div>
      </div>

      <div class="modal-section">
        <h4>Recommended Action</h4>
        <div id="modal-action">—</div>
      </div>

      <div class="action-row" id="modal-action-buttons">
        <button class="btn-approve" id="btn-approve-incident" onclick="decideIncident('approve')">Approve</button>
        <button class="btn-reject" id="btn-reject-incident" onclick="decideIncident('reject')">Reject</button>
      </div>
      <div class="decision-note" id="modal-decision-note"></div>
    </div>
  </div>

<script>
let currentIncidentId = null;
let historyLoaded = 0;
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

async function clearDashboard() {
  if (!confirm('Clear all alerts, logs and incidents? This cannot be undone.')) return;
  await fetch('/api/clear', { method: 'POST' });
  refresh();
  if (typeof loadIncidents === 'function') loadIncidents();
}

function renderRows(elId, events, emptyText) {
  const tbody = document.getElementById(elId);
  if (events.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" class="empty">${emptyText}</td></tr>`;
    return;
  }
  tbody.innerHTML = events.map(e => `
    <tr>
      <td>${e.time}</td>
      <td><span class="badge ${e.type}">${verdictLabel(e.type)}</span></td>
      <td>${e.attack_type || ''}</td>
      <td>${e.severity ? `<span class="sev ${e.severity}">${e.severity}</span>` : ''}</td>
      <td>${e.flow}</td>
      <td>${e.detail}${e.mitre_id ? `<span class="mitre-tag">MITRE ${e.mitre_id}</span>` : ''}</td>
    </tr>
  `).join('');
}

async function loadHistory() {
  try {
    const res = await fetch('/api/history');
    const data = await res.json();

    const maxVal = Math.max(...data.trend.values, 1);
    const chart = document.getElementById('trend-chart');
    chart.innerHTML = data.trend.values.map(v =>
      `<div class="trend-bar" data-count="${v}" style="height:${Math.max((v / maxVal) * 100, 2)}%"></div>`
    ).join('');

    const labels = document.getElementById('trend-labels');
    const step = Math.ceil(data.trend.labels.length / 6);
    labels.innerHTML = data.trend.labels
      .filter((_, i) => i % step === 0)
      .map(l => `<span>${l}</span>`).join('');

    const topIpsEl = document.getElementById('top-ips');
    if (data.top_ips.length === 0) {
      topIpsEl.innerHTML = '<div class="empty">No attacker activity yet</div>';
    } else {
      topIpsEl.innerHTML = data.top_ips.map(ip => `
        <div class="ip-row"><span>${ip.ip}</span><span class="ip-count">${ip.count}</span></div>
      `).join('');
    }
  } catch (err) {
    console.error('Failed to load history', err);
  }
}

function statusLabel(status) {
  return (status || '').replace(/_/g, ' ');
}

async function loadIncidents() {
  try {
    const res = await fetch('/api/incidents');
    const data = await res.json();

    const tbody = document.getElementById('incidents-body');
    if (data.incidents.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" class="empty">No incidents yet</td></tr>';
      return;
    }

    tbody.innerHTML = data.incidents.map(inc => `
      <tr class="incident-row" onclick="openIncidentModal('${inc.id}')">
        <td><strong>${inc.id}</strong></td>
        <td><span class="status-pill ${inc.status}">${statusLabel(inc.status)}</span></td>
        <td>${inc.severity ? `<span class="sev ${inc.severity}">${inc.severity}</span>` : '—'}</td>
        <td>${inc.mitre_id ? `${inc.mitre_id} — ${inc.mitre_name || ''}` : '—'}</td>
        <td>${inc.source_ip || '—'}</td>
        <td>${(inc.created_at || '').split(' ')[1] || inc.created_at || ''}</td>
      </tr>
    `).join('');
  } catch (err) {
    console.error('Failed to load incidents', err);
  }
}

async function openIncidentModal(incidentId) {
  currentIncidentId = incidentId;

  try {
    const res = await fetch(`/api/incidents/${incidentId}`);
    if (!res.ok) return;
    const inc = await res.json();

    document.getElementById('modal-title').textContent = inc.id;
    document.getElementById('modal-subtitle').textContent =
      `${inc.flow || ''} · ${inc.attack_type || 'Unclassified'} · created ${inc.created_at || ''}`;

    document.getElementById('modal-status').innerHTML =
      `<span class="status-pill ${inc.status}">${statusLabel(inc.status)}</span>`;
    document.getElementById('modal-severity').textContent = inc.severity || '—';
    document.getElementById('modal-confidence').textContent =
      (inc.confidence !== null && inc.confidence !== undefined) ? `${inc.confidence}%` : '—';

    document.getElementById('modal-mitre').textContent =
      inc.mitre_id ? `${inc.mitre_id} — ${inc.mitre_name}` : 'Not yet classified';

    document.getElementById('modal-assessment').textContent =
      inc.ai_assessment || 'No assessment yet — investigation may still be running.';

    const timelineEl = document.getElementById('modal-timeline');
    if (inc.timeline && inc.timeline.length > 0) {
      timelineEl.innerHTML = inc.timeline.map(t => `
        <div class="timeline-item">
          <div class="timeline-time">${t.time || ''}</div>
          <div>${t.event || ''}</div>
        </div>
      `).join('');
    } else {
      timelineEl.innerHTML = '<div class="empty">No timeline yet.</div>';
    }

    const evidenceEl = document.getElementById('modal-evidence');
    if (inc.evidence && inc.evidence.length > 0) {
      evidenceEl.innerHTML = inc.evidence.map(e => `
        <div class="evidence-item">
          <div class="evidence-tool">${e.tool}(${JSON.stringify(e.args || {})})</div>
          <div class="evidence-result">${JSON.stringify(e.result, null, 2)}</div>
        </div>
      `).join('');
    } else {
      evidenceEl.innerHTML = '<div class="empty">No tool calls recorded yet.</div>';
    }

    document.getElementById('modal-action').textContent = inc.recommended_action || 'No recommendation yet.';

    const buttons = document.getElementById('modal-action-buttons');
    const note = document.getElementById('modal-decision-note');

    if (inc.human_decision) {
      buttons.style.display = 'none';
      note.textContent = `Already ${inc.human_decision} by analyst.`;
    } else if (inc.status !== 'RESPONSE_RECOMMENDED') {
      buttons.style.display = 'none';
      note.textContent = 'Waiting for AI investigation to finish before a decision can be made.';
    } else {
      buttons.style.display = 'flex';
      note.textContent = '';
    }

    document.getElementById('incident-modal').classList.add('open');
  } catch (err) {
    console.error('Failed to load incident detail', err);
  }
}

function closeIncidentModal() {
  document.getElementById('incident-modal').classList.remove('open');
  currentIncidentId = null;
}

async function decideIncident(action) {
  if (!currentIncidentId) return;

  try {
    await fetch(`/api/incidents/${currentIncidentId}/${action}`, { method: 'POST' });
    await openIncidentModal(currentIncidentId);   // refresh modal with new status
    loadIncidents();                              // refresh table in background
  } catch (err) {
    console.error('Failed to submit decision', err);
  }
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

    const attackNameEl = document.getElementById('attack-name');
    if (verdict === 'attacks' && data.current.attack_type) {
      attackNameEl.textContent = data.current.attack_type;
      attackNameEl.style.display = 'block';
    } else {
      attackNameEl.style.display = 'none';
    }

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

    // refresh history + incidents every ~10s (every 5th tick), not every 2s — both hit the DB
    historyLoaded++;
    if (historyLoaded % 5 === 1) {
      loadHistory();
      loadIncidents();
    }

  } catch (err) {
    console.error('Failed to refresh dashboard', err);
  }
}

refresh();
loadIncidents();
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
        # While a threat is still "active" (within the window), keep the banner showing
        # the last attack rather than whatever the latest single flow was — otherwise a
        # normal flow landing between attack flows flickers the banner back to green.
        if threat_active and dashboard_state["last_attack"]:
            display_current = dashboard_state["last_attack"]
        else:
            display_current = dashboard_state["current"]
        payload = {
            "stats": dashboard_state["stats"],
            "events": dashboard_state["events"],
            "current": display_current,
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


@app.route("/api/clear", methods=["POST"])
def api_clear():
    """Wipes alerts/incidents/log history so a fresh test run starts clean.
    Does not touch whether the scan engine itself is running."""
    with state_lock:
        dashboard_state["stats"] = {"total": 0, "attacks": 0, "zero_day": 0, "normal": 0, "skipped": 0}
        dashboard_state["events"] = []
        dashboard_state["current"] = {"verdict": "IDLE", "detail": "Cleared", "flow": "", "time": None, "attack_type": None}
        dashboard_state["last_alert_time"] = 0
        dashboard_state["last_attack"] = None

    with scan_tracker_lock:
        scan_tracker.clear()
        flagged_scanners.clear()

    with db_lock:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("DELETE FROM events")
        conn.commit()
        conn.close()

    incident_engine.clear_all_incidents()

    return jsonify({"cleared": True})


@app.route("/api/history")
def api_history():
    HOURS = 6
    BUCKET_MINUTES = 15
    cutoff = time.time() - (HOURS * 3600)

    with db_lock:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row

        # trend buckets — attack/zero-day counts per time window
        rows = conn.execute(
            "SELECT epoch, type FROM events WHERE epoch >= ? AND type IN ('attacks','zero_day')",
            (cutoff,)
        ).fetchall()

        # top attacker IPs (all-time, attacks + zero-day only)
        top_ips = conn.execute(
            "SELECT source_ip, COUNT(*) as count FROM events "
            "WHERE type IN ('attacks','zero_day') AND source_ip IS NOT NULL "
            "GROUP BY source_ip ORDER BY count DESC LIMIT 8"
        ).fetchall()

        # severity breakdown (all-time)
        severity_rows = conn.execute(
            "SELECT severity, COUNT(*) as count FROM events "
            "WHERE severity IS NOT NULL AND severity != 'Info' "
            "GROUP BY severity"
        ).fetchall()

        # most recent critical/high events for a quick-glance list
        recent_serious = conn.execute(
            "SELECT timestamp, flow, detail, severity, mitre_id, mitre_name FROM events "
            "WHERE severity IN ('Critical','High') ORDER BY epoch DESC LIMIT 10"
        ).fetchall()

        conn.close()

    bucket_size = BUCKET_MINUTES * 60
    num_buckets = int((HOURS * 3600) / bucket_size)
    now = time.time()
    buckets = [0] * num_buckets

    for row in rows:
        age = now - row["epoch"]
        bucket_index = num_buckets - 1 - int(age // bucket_size)
        if 0 <= bucket_index < num_buckets:
            buckets[bucket_index] += 1

    bucket_labels = []
    for i in range(num_buckets):
        minutes_ago = (num_buckets - i) * BUCKET_MINUTES
        bucket_labels.append(f"-{minutes_ago}m")

    return jsonify({
        "trend": {"labels": bucket_labels, "values": buckets},
        "top_ips": [{"ip": r["source_ip"], "count": r["count"]} for r in top_ips],
        "severity_breakdown": {r["severity"]: r["count"] for r in severity_rows},
        "recent_serious": [dict(r) for r in recent_serious]
    })


# ============================================================
# INCIDENT ROUTES
# Thin wrappers around incident_engine — no business logic here,
# this file only ever displays/relays what the engine already did.
# ============================================================

@app.route("/api/incidents")
def api_incidents_list():
    incidents = incident_engine.list_incidents(limit=100)
    return jsonify({"incidents": incidents})


@app.route("/api/incidents/<incident_id>")
def api_incident_detail(incident_id):
    incident = incident_engine.get_incident(incident_id)
    if not incident:
        return jsonify({"error": "not found"}), 404

    # timeline/evidence are stored as JSON text — parse them back out
    # for the frontend so it doesn't have to double-decode.
    try:
        incident["timeline"] = json.loads(incident["timeline_json"]) if incident["timeline_json"] else []
    except (json.JSONDecodeError, TypeError):
        incident["timeline"] = []

    try:
        incident["evidence"] = json.loads(incident["evidence_json"]) if incident["evidence_json"] else []
    except (json.JSONDecodeError, TypeError):
        incident["evidence"] = []

    return jsonify(incident)


@app.route("/api/incidents/<incident_id>/approve", methods=["POST"])
def api_incident_approve(incident_id):
    incident = incident_engine.get_incident(incident_id)
    if not incident:
        return jsonify({"error": "not found"}), 404

    incident_engine.approve_incident(incident_id)
    return jsonify({"approved": True, "incident_id": incident_id})


@app.route("/api/incidents/<incident_id>/reject", methods=["POST"])
def api_incident_reject(incident_id):
    incident = incident_engine.get_incident(incident_id)
    if not incident:
        return jsonify({"error": "not found"}), 404

    incident_engine.reject_incident(incident_id)
    return jsonify({"rejected": True, "incident_id": incident_id})


if __name__ == "__main__":
    app.run(debug=False, port=5000)