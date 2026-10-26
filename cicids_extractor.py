from scapy.all import sniff, IP, TCP, UDP
import statistics


# ============================================================
# SETTINGS
# ============================================================

PACKET_COUNT = 10
LOCAL_IP = "192.168.10.100"

# Active/Idle threshold in seconds
ACTIVE_IDLE_THRESHOLD = 1.0

# Bulk detection threshold
BULK_PACKET_THRESHOLD = 4
BULK_TIME_THRESHOLD = 1.0


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def safe_mean(values):
    return statistics.mean(values) if values else 0


def safe_std(values):
    return statistics.stdev(values) if len(values) > 1 else 0


def safe_variance(values):
    return statistics.variance(values) if len(values) > 1 else 0


def calculate_iat(times):

    if len(times) < 2:
        return []

    times = sorted(times)

    return [
        (times[i] - times[i - 1]) * 1_000_000
        for i in range(1, len(times))
    ]


def get_tcp_flags(packet):

    flags = {
        "FIN": 0,
        "SYN": 0,
        "RST": 0,
        "PSH": 0,
        "ACK": 0,
        "URG": 0,
        "CWR": 0,
        "ECE": 0
    }

    if TCP not in packet:
        return flags

    tcp_flags = packet[TCP].flags

    flags["FIN"] = int("F" in tcp_flags)
    flags["SYN"] = int("S" in tcp_flags)
    flags["RST"] = int("R" in tcp_flags)
    flags["PSH"] = int("P" in tcp_flags)
    flags["ACK"] = int("A" in tcp_flags)
    flags["URG"] = int("U" in tcp_flags)
    flags["CWR"] = int("C" in tcp_flags)
    flags["ECE"] = int("E" in tcp_flags)

    return flags


def calculate_active_idle(times):

    if len(times) < 2:
        return [], []

    times = sorted(times)

    active_periods = []
    idle_periods = []

    active_start = times[0]
    previous_time = times[0]

    for current_time in times[1:]:

        gap = current_time - previous_time

        if gap > ACTIVE_IDLE_THRESHOLD:

            active_duration = previous_time - active_start

            if active_duration > 0:
                active_periods.append(
                    active_duration * 1_000_000
                )

            idle_periods.append(
                gap * 1_000_000
            )

            active_start = current_time

        previous_time = current_time

    final_active = previous_time - active_start

    if final_active > 0:
        active_periods.append(
            final_active * 1_000_000
        )

    return active_periods, idle_periods


def calculate_bulk_features(times, lengths):

    if len(times) < BULK_PACKET_THRESHOLD:
        return 0, 0, 0

    times = sorted(times)

    total_bytes = 0
    total_packets = 0

    bulk_bytes = 0
    bulk_packets = 0
    bulk_duration = 0

    for i in range(len(times)):

        total_bytes += lengths[i]
        total_packets += 1

    duration = times[-1] - times[0]

    if duration > 0:

        bulk_bytes = total_bytes
        bulk_packets = total_packets
        bulk_duration = duration

    if bulk_packets >= BULK_PACKET_THRESHOLD:

        avg_bytes_per_bulk = bulk_bytes
        avg_packets_per_bulk = bulk_packets

        avg_bulk_rate = (
            bulk_bytes / bulk_duration
            if bulk_duration > 0
            else 0
        )

        return (
            avg_bytes_per_bulk,
            avg_packets_per_bulk,
            avg_bulk_rate
        )

    return 0, 0, 0


# ============================================================
# CAPTURE PACKETS
# ============================================================

print(f"\nScanning for {PACKET_COUNT} packets...")
print("Generate some internet traffic...\n")

packets = sniff(count=PACKET_COUNT)

print(f"Packets captured: {len(packets)}\n")


# ============================================================
# FLOW STORAGE
# ============================================================

flows = {}


# ============================================================
# PROCESS PACKETS
# ============================================================

for packet in packets:

    if IP not in packet:
        continue


    source_ip = packet[IP].src
    destination_ip = packet[IP].dst

    protocol = packet[IP].proto


    # --------------------------------------------------------
    # GET PORTS
    # --------------------------------------------------------

    source_port = 0
    destination_port = 0

    if TCP in packet:

        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

    elif UDP in packet:

        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

    else:
        continue


    packet_length = len(packet)
    packet_time = float(packet.time)


    # --------------------------------------------------------
    # CREATE BIDIRECTIONAL FLOW KEY
    # --------------------------------------------------------

    endpoint1 = (
        source_ip,
        source_port
    )

    endpoint2 = (
        destination_ip,
        destination_port
    )

    flow_key = (
        tuple(sorted([endpoint1, endpoint2]))
        + (protocol,)
    )


    # --------------------------------------------------------
    # DETERMINE DIRECTION
    #
    # LOCAL MACHINE -> DESTINATION = FORWARD
    # DESTINATION -> LOCAL MACHINE = BACKWARD
    # --------------------------------------------------------

    if source_ip == LOCAL_IP:

        direction = "forward"

        forward_endpoint = endpoint1
        backward_endpoint = endpoint2

    elif destination_ip == LOCAL_IP:

        direction = "backward"

        forward_endpoint = endpoint2
        backward_endpoint = endpoint1

    else:

        # Fallback for packets not involving local IP

        if endpoint1 < endpoint2:

            direction = "forward"

            forward_endpoint = endpoint1
            backward_endpoint = endpoint2

        else:

            direction = "backward"

            forward_endpoint = endpoint2
            backward_endpoint = endpoint1


    # --------------------------------------------------------
    # CREATE FLOW
    # --------------------------------------------------------

    if flow_key not in flows:

        flows[flow_key] = {

            # Endpoints

            "forward_endpoint": forward_endpoint,
            "backward_endpoint": backward_endpoint,

            "destination_port":
                backward_endpoint[1],


            # Time

            "start_time": packet_time,
            "end_time": packet_time,


            # Packet lengths

            "fwd_lengths": [],
            "bwd_lengths": [],
            "all_lengths": [],


            # Packet timestamps

            "fwd_times": [],
            "bwd_times": [],
            "all_times": [],


            # Header lengths

            "fwd_header_lengths": [],
            "bwd_header_lengths": [],


            # TCP Window values

            "fwd_initial_window": None,
            "bwd_initial_window": None,


            # Active data packets

            "fwd_active_data_packets": 0,


            # Segment sizes

            "fwd_segment_sizes": [],


            # Flags

            "fwd_psh": 0,
            "bwd_psh": 0,

            "fwd_urg": 0,
            "bwd_urg": 0,


            # TCP Flag counts

            "FIN": 0,
            "SYN": 0,
            "RST": 0,
            "PSH": 0,
            "ACK": 0,
            "URG": 0,
            "CWR": 0,
            "ECE": 0
        }


    flow = flows[flow_key]


    # --------------------------------------------------------
    # UPDATE TIME
    # --------------------------------------------------------

    flow["start_time"] = min(
        flow["start_time"],
        packet_time
    )

    flow["end_time"] = max(
        flow["end_time"],
        packet_time
    )


    # --------------------------------------------------------
    # STORE OVERALL DATA
    # --------------------------------------------------------

    flow["all_lengths"].append(
        packet_length
    )

    flow["all_times"].append(
        packet_time
    )


    # --------------------------------------------------------
    # HEADER LENGTH
    # --------------------------------------------------------

    header_length = 0

    if TCP in packet:

        header_length = (
            packet[TCP].dataofs * 4
        )

    elif UDP in packet:

        header_length = 8


    # --------------------------------------------------------
    # TCP FLAGS
    # --------------------------------------------------------

    tcp_flags = get_tcp_flags(packet)

    for flag in tcp_flags:

        flow[flag] += tcp_flags[flag]


    # --------------------------------------------------------
    # FORWARD PACKET
    # --------------------------------------------------------

    if direction == "forward":

        flow["fwd_lengths"].append(
            packet_length
        )

        flow["fwd_times"].append(
            packet_time
        )

        flow["fwd_header_lengths"].append(
            header_length
        )

        flow["fwd_segment_sizes"].append(
            packet_length
        )


        # PSH / URG

        flow["fwd_psh"] += (
            tcp_flags["PSH"]
        )

        flow["fwd_urg"] += (
            tcp_flags["URG"]
        )


        # TCP Initial Window

        if (
            TCP in packet
            and flow["fwd_initial_window"] is None
        ):

            flow["fwd_initial_window"] = (
                packet[TCP].window
            )


        # Forward Active Data Packets

        if TCP in packet:

            payload_length = len(
                bytes(packet[TCP].payload)
            )

            if payload_length > 0:

                flow[
                    "fwd_active_data_packets"
                ] += 1


    # --------------------------------------------------------
    # BACKWARD PACKET
    # --------------------------------------------------------

    else:

        flow["bwd_lengths"].append(
            packet_length
        )

        flow["bwd_times"].append(
            packet_time
        )

        flow["bwd_header_lengths"].append(
            header_length
        )


        # PSH / URG

        flow["bwd_psh"] += (
            tcp_flags["PSH"]
        )

        flow["bwd_urg"] += (
            tcp_flags["URG"]
        )


        # TCP Initial Window

        if (
            TCP in packet
            and flow["bwd_initial_window"] is None
        ):

            flow["bwd_initial_window"] = (
                packet[TCP].window
            )


# ============================================================
# DISPLAY FEATURES
# ============================================================

print("\n")
print("=" * 60)
print("CICIDS FLOW FEATURES")
print("=" * 60)


for flow_key, flow in flows.items():

    # --------------------------------------------------------
    # BASIC ARRAYS
    # --------------------------------------------------------

    fwd_lengths = flow["fwd_lengths"]
    bwd_lengths = flow["bwd_lengths"]
    all_lengths = flow["all_lengths"]

    fwd_times = sorted(flow["fwd_times"])
    bwd_times = sorted(flow["bwd_times"])
    all_times = sorted(flow["all_times"])


    # --------------------------------------------------------
    # PACKET COUNTS
    # --------------------------------------------------------

    total_fwd_packets = len(
        fwd_lengths
    )

    total_bwd_packets = len(
        bwd_lengths
    )


    # --------------------------------------------------------
    # BYTE COUNTS
    # --------------------------------------------------------

    total_fwd_length = sum(
        fwd_lengths
    )

    total_bwd_length = sum(
        bwd_lengths
    )

    total_bytes = (
        total_fwd_length
        + total_bwd_length
    )


    # --------------------------------------------------------
    # FLOW DURATION
    # CICIDS uses microseconds
    # --------------------------------------------------------

    flow_duration = (

        flow["end_time"]
        - flow["start_time"]

    ) * 1_000_000


    duration_seconds = (
        flow_duration / 1_000_000
    )


    # --------------------------------------------------------
    # FLOW RATES
    # --------------------------------------------------------

    if duration_seconds > 0:

        flow_bytes_per_second = (

            total_bytes
            / duration_seconds

        )

        flow_packets_per_second = (

            len(all_lengths)
            / duration_seconds

        )

        fwd_packets_per_second = (

            total_fwd_packets
            / duration_seconds

        )

        bwd_packets_per_second = (

            total_bwd_packets
            / duration_seconds

        )

    else:

        flow_bytes_per_second = 0
        flow_packets_per_second = 0

        fwd_packets_per_second = 0
        bwd_packets_per_second = 0


    # --------------------------------------------------------
    # IAT FEATURES
    # --------------------------------------------------------

    flow_iat = calculate_iat(
        all_times
    )

    fwd_iat = calculate_iat(
        fwd_times
    )

    bwd_iat = calculate_iat(
        bwd_times
    )


    # --------------------------------------------------------
    # ACTIVE / IDLE FEATURES
    # --------------------------------------------------------

    active_periods, idle_periods = (

        calculate_active_idle(
            all_times
        )

    )


    # --------------------------------------------------------
    # BULK FEATURES
    # --------------------------------------------------------

    (

        fwd_avg_bytes_bulk,
        fwd_avg_packets_bulk,
        fwd_avg_bulk_rate

    ) = calculate_bulk_features(

        fwd_times,
        fwd_lengths

    )


    (

        bwd_avg_bytes_bulk,
        bwd_avg_packets_bulk,
        bwd_avg_bulk_rate

    ) = calculate_bulk_features(

        bwd_times,
        bwd_lengths

    )


    # --------------------------------------------------------
    # DOWN / UP RATIO
    # --------------------------------------------------------

    if total_fwd_packets > 0:

        down_up_ratio = (

            total_bwd_packets
            / total_fwd_packets

        )

    else:

        down_up_ratio = 0


    # --------------------------------------------------------
    # PACKET SIZE
    # --------------------------------------------------------

    average_packet_size = safe_mean(
        all_lengths
    )

    avg_fwd_segment_size = safe_mean(
        fwd_lengths
    )

    avg_bwd_segment_size = safe_mean(
        bwd_lengths
    )


    # --------------------------------------------------------
    # INITIAL WINDOW
    # --------------------------------------------------------

    init_win_fwd = (

        flow["fwd_initial_window"]

        if flow["fwd_initial_window"] is not None

        else 0

    )

    init_win_bwd = (

        flow["bwd_initial_window"]

        if flow["bwd_initial_window"] is not None

        else 0

    )


    # --------------------------------------------------------
    # MIN SEGMENT SIZE FORWARD
    # --------------------------------------------------------

    min_seg_size_forward = (

        min(flow["fwd_segment_sizes"])

        if flow["fwd_segment_sizes"]

        else 0

    )


    # ========================================================
    # DISPLAY FLOW
    # ========================================================

    print("\n")
    print("FLOW:")
    print(flow_key)

    print("-" * 60)


    # --------------------------------------------------------
    # BASIC FEATURES
    # --------------------------------------------------------

    print(
        "Forward Endpoint:",
        flow["forward_endpoint"]
    )

    print(
        "Backward Endpoint:",
        flow["backward_endpoint"]
    )

    print()

    print(
        "Destination Port:",
        flow["destination_port"]
    )

    print(
        "Flow Duration:",
        round(flow_duration, 4)
    )

    print(
        "Total Fwd Packets:",
        total_fwd_packets
    )

    print(
        "Total Backward Packets:",
        total_bwd_packets
    )

    print(
        "Total Length of Fwd Packets:",
        total_fwd_length
    )

    print(
        "Total Length of Bwd Packets:",
        total_bwd_length
    )


    # --------------------------------------------------------
    # FORWARD PACKET FEATURES
    # --------------------------------------------------------

    print(
        "\n--- FORWARD PACKET LENGTH FEATURES ---"
    )

    print(
        "Fwd Packet Length Max:",
        max(fwd_lengths)
        if fwd_lengths
        else 0
    )

    print(
        "Fwd Packet Length Min:",
        min(fwd_lengths)
        if fwd_lengths
        else 0
    )

    print(
        "Fwd Packet Length Mean:",
        round(
            safe_mean(fwd_lengths),
            4
        )
    )

    print(
        "Fwd Packet Length Std:",
        round(
            safe_std(fwd_lengths),
            4
        )
    )


    # --------------------------------------------------------
    # BACKWARD PACKET FEATURES
    # --------------------------------------------------------

    print(
        "\n--- BACKWARD PACKET LENGTH FEATURES ---"
    )

    print(
        "Bwd Packet Length Max:",
        max(bwd_lengths)
        if bwd_lengths
        else 0
    )

    print(
        "Bwd Packet Length Min:",
        min(bwd_lengths)
        if bwd_lengths
        else 0
    )

    print(
        "Bwd Packet Length Mean:",
        round(
            safe_mean(bwd_lengths),
            4
        )
    )

    print(
        "Bwd Packet Length Std:",
        round(
            safe_std(bwd_lengths),
            4
        )
    )


    # --------------------------------------------------------
    # FLOW RATE
    # --------------------------------------------------------

    print(
        "\n--- FLOW RATE FEATURES ---"
    )

    print(
        "Flow Bytes/s:",
        round(
            flow_bytes_per_second,
            4
        )
    )

    print(
        "Flow Packets/s:",
        round(
            flow_packets_per_second,
            4
        )
    )


    # --------------------------------------------------------
    # FLOW IAT
    # --------------------------------------------------------

    print(
        "\n--- FLOW IAT FEATURES ---"
    )

    print(
        "Flow IAT Mean:",
        round(
            safe_mean(flow_iat),
            4
        )
    )

    print(
        "Flow IAT Std:",
        round(
            safe_std(flow_iat),
            4
        )
    )

    print(
        "Flow IAT Max:",
        round(
            max(flow_iat)
            if flow_iat
            else 0,
            4
        )
    )

    print(
        "Flow IAT Min:",
        round(
            min(flow_iat)
            if flow_iat
            else 0,
            4
        )
    )


    # --------------------------------------------------------
    # FORWARD IAT
    # --------------------------------------------------------

    print(
        "\n--- FORWARD IAT FEATURES ---"
    )

    print(
        "Fwd IAT Total:",
        round(sum(fwd_iat), 4)
    )

    print(
        "Fwd IAT Mean:",
        round(
            safe_mean(fwd_iat),
            4
        )
    )

    print(
        "Fwd IAT Std:",
        round(
            safe_std(fwd_iat),
            4
        )
    )

    print(
        "Fwd IAT Max:",
        round(
            max(fwd_iat)
            if fwd_iat
            else 0,
            4
        )
    )

    print(
        "Fwd IAT Min:",
        round(
            min(fwd_iat)
            if fwd_iat
            else 0,
            4
        )
    )


    # --------------------------------------------------------
    # BACKWARD IAT
    # --------------------------------------------------------

    print(
        "\n--- BACKWARD IAT FEATURES ---"
    )

    print(
        "Bwd IAT Total:",
        round(sum(bwd_iat), 4)
    )

    print(
        "Bwd IAT Mean:",
        round(
            safe_mean(bwd_iat),
            4
        )
    )

    print(
        "Bwd IAT Std:",
        round(
            safe_std(bwd_iat),
            4
        )
    )

    print(
        "Bwd IAT Max:",
        round(
            max(bwd_iat)
            if bwd_iat
            else 0,
            4
        )
    )

    print(
        "Bwd IAT Min:",
        round(
            min(bwd_iat)
            if bwd_iat
            else 0,
            4
        )
    )


    # --------------------------------------------------------
    # FLAGS
    # --------------------------------------------------------

    print(
        "\n--- DIRECTIONAL FLAG FEATURES ---"
    )

    print(
        "Fwd PSH Flags:",
        flow["fwd_psh"]
    )

    print(
        "Bwd PSH Flags:",
        flow["bwd_psh"]
    )

    print(
        "Fwd URG Flags:",
        flow["fwd_urg"]
    )

    print(
        "Bwd URG Flags:",
        flow["bwd_urg"]
    )


    # --------------------------------------------------------
    # TCP FLAGS
    # --------------------------------------------------------

    print(
        "\n--- TCP FLAG COUNT FEATURES ---"
    )

    print(
        "FIN Flag Count:",
        flow["FIN"]
    )

    print(
        "SYN Flag Count:",
        flow["SYN"]
    )

    print(
        "RST Flag Count:",
        flow["RST"]
    )

    print(
        "PSH Flag Count:",
        flow["PSH"]
    )

    print(
        "ACK Flag Count:",
        flow["ACK"]
    )

    print(
        "URG Flag Count:",
        flow["URG"]
    )

    print(
        "CWR Flag Count:",
        flow["CWR"]
    )

    print(
        "ECE Flag Count:",
        flow["ECE"]
    )


    # --------------------------------------------------------
    # HEADER LENGTH
    # --------------------------------------------------------

    print(
        "\n--- HEADER LENGTH FEATURES ---"
    )

    print(
        "Fwd Header Length:",
        sum(flow["fwd_header_lengths"])
    )

    print(
        "Bwd Header Length:",
        sum(flow["bwd_header_lengths"])
    )


    # --------------------------------------------------------
    # DIRECTIONAL PACKET RATE
    # --------------------------------------------------------

    print(
        "\n--- DIRECTIONAL PACKET RATE FEATURES ---"
    )

    print(
        "Fwd Packets/s:",
        round(
            fwd_packets_per_second,
            4
        )
    )

    print(
        "Bwd Packets/s:",
        round(
            bwd_packets_per_second,
            4
        )
    )


    # --------------------------------------------------------
    # OVERALL PACKET LENGTH
    # --------------------------------------------------------

    print(
        "\n--- OVERALL PACKET LENGTH FEATURES ---"
    )

    print(
        "Min Packet Length:",
        min(all_lengths)
        if all_lengths
        else 0
    )

    print(
        "Max Packet Length:",
        max(all_lengths)
        if all_lengths
        else 0
    )

    print(
        "Packet Length Mean:",
        round(
            safe_mean(all_lengths),
            4
        )
    )

    print(
        "Packet Length Std:",
        round(
            safe_std(all_lengths),
            4
        )
    )

    print(
        "Packet Length Variance:",
        round(
            safe_variance(all_lengths),
            4
        )
    )


    # --------------------------------------------------------
    # ADDITIONAL FEATURES
    # --------------------------------------------------------

    print(
        "\n--- ADDITIONAL CICIDS FEATURES ---"
    )

    print(
        "Down/Up Ratio:",
        round(
            down_up_ratio,
            4
        )
    )

    print(
        "Average Packet Size:",
        round(
            average_packet_size,
            4
        )
    )

    print(
        "Avg Fwd Segment Size:",
        round(
            avg_fwd_segment_size,
            4
        )
    )

    print(
        "Avg Bwd Segment Size:",
        round(
            avg_bwd_segment_size,
            4
        )
    )


    # --------------------------------------------------------
    # BULK FEATURES
    # --------------------------------------------------------

    print(
        "\n--- BULK FEATURES ---"
    )

    print(
        "Fwd Avg Bytes/Bulk:",
        round(
            fwd_avg_bytes_bulk,
            4
        )
    )

    print(
        "Fwd Avg Packets/Bulk:",
        round(
            fwd_avg_packets_bulk,
            4
        )
    )

    print(
        "Fwd Avg Bulk Rate:",
        round(
            fwd_avg_bulk_rate,
            4
        )
    )

    print(
        "Bwd Avg Bytes/Bulk:",
        round(
            bwd_avg_bytes_bulk,
            4
        )
    )

    print(
        "Bwd Avg Packets/Bulk:",
        round(
            bwd_avg_packets_bulk,
            4
        )
    )

    print(
        "Bwd Avg Bulk Rate:",
        round(
            bwd_avg_bulk_rate,
            4
        )
    )


    # --------------------------------------------------------
    # SUBFLOW FEATURES
    # --------------------------------------------------------

    print(
        "\n--- SUBFLOW FEATURES ---"
    )

    # One captured flow is treated as one subflow
    print(
        "Subflow Fwd Packets:",
        total_fwd_packets
    )

    print(
        "Subflow Fwd Bytes:",
        total_fwd_length
    )

    print(
        "Subflow Bwd Packets:",
        total_bwd_packets
    )

    print(
        "Subflow Bwd Bytes:",
        total_bwd_length
    )


    # --------------------------------------------------------
    # TCP WINDOW FEATURES
    # --------------------------------------------------------

    print(
        "\n--- TCP WINDOW FEATURES ---"
    )

    print(
        "Init_Win_bytes_forward:",
        init_win_fwd
    )

    print(
        "Init_Win_bytes_backward:",
        init_win_bwd
    )


    # --------------------------------------------------------
    # DATA PACKET FEATURES
    # --------------------------------------------------------

    print(
        "\n--- DATA PACKET FEATURES ---"
    )

    print(
        "act_data_pkt_fwd:",
        flow["fwd_active_data_packets"]
    )

    print(
        "min_seg_size_forward:",
        min_seg_size_forward
    )


    # --------------------------------------------------------
    # ACTIVE / IDLE FEATURES
    # --------------------------------------------------------

    print(
        "\n--- ACTIVE / IDLE FEATURES ---"
    )

    print(
        "Active Mean:",
        round(
            safe_mean(active_periods),
            4
        )
    )

    print(
        "Active Std:",
        round(
            safe_std(active_periods),
            4
        )
    )

    print(
        "Active Max:",
        round(
            max(active_periods)
            if active_periods
            else 0,
            4
        )
    )

    print(
        "Active Min:",
        round(
            min(active_periods)
            if active_periods
            else 0,
            4
        )
    )

    print()

    print(
        "Idle Mean:",
        round(
            safe_mean(idle_periods),
            4
        )
    )

    print(
        "Idle Std:",
        round(
            safe_std(idle_periods),
            4
        )
    )

    print(
        "Idle Max:",
        round(
            max(idle_periods)
            if idle_periods
            else 0,
            4
        )
    )

    print(
        "Idle Min:",
        round(
            min(idle_periods)
            if idle_periods
            else 0,
            4
        )
    )


    print()
    print("-" * 60)


# ============================================================
# FINAL RESULT
# ============================================================

print()
print("Total Flows Detected:", len(flows))