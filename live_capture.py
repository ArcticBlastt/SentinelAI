from scapy.all import sniff, IP, TCP, UDP

print("Scanning for packets...")

packets = sniff(count=10)

print("Packets:", len(packets))


# Dictionary for storing flows
flows = {}


for packet in packets:

    if IP not in packet:
        continue

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst
    protocol = packet[IP].proto
    packet_length = len(packet)

    source_port = None
    destination_port = None


    # Get port numbers
    if TCP in packet:

        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

    elif UDP in packet:

        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

    else:
        # Ignore packets without TCP or UDP
        continue


    print("\nSource IP:", source_ip)
    print("Destination IP:", destination_ip)
    print("Protocol:", protocol)
    print("Source Port:", source_port)
    print("Destination Port:", destination_port)
    print("Packet Length:", packet_length)


    # Create endpoints
    endpoint1 = (source_ip, source_port)
    endpoint2 = (destination_ip, destination_port)


    # Create bidirectional flow key
    flow_key = tuple(sorted([endpoint1, endpoint2])) + (protocol,)


    # Create the flow if it doesn't already exist
    if flow_key not in flows:

        flows[flow_key] = {

            "packets": 0,
            "total_bytes": 0,
            "packet_lengths": [],
            "start_time": packet.time,
            "end_time": packet.time

        }


    # Add packet to flow

    flows[flow_key]["packets"] += 1

    flows[flow_key]["total_bytes"] += packet_length

    flows[flow_key]["packet_lengths"].append(packet_length)

    # Update flow end time
    flows[flow_key]["end_time"] = packet.time


# =====================================================
# DISPLAY FLOWS
# =====================================================

print("\n--- FLOWS DETECTED ---\n")


for flow_key, flow_data in flows.items():

    print("Flow:", flow_key)

    print("Total Packets:", flow_data["packets"])

    print("Total Bytes:", flow_data["total_bytes"])

    print("Flow Duration:",
          round(
              float(flow_data["end_time"])
              - float(flow_data["start_time"]),
              6
          ),
          "seconds"
    )

    print("--------------------------")