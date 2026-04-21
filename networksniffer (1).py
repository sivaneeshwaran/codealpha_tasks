from scapy.all import sniff, IP, TCP, UDP, Raw

# Function to process each packet
def analyze_packet(packet):
    print("\n--- Packet Captured ---")

    # Check if packet has IP layer
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        print(f"Source IP      : {ip_layer.src}")
        print(f"Destination IP : {ip_layer.dst}")
        print(f"Protocol       : {ip_layer.proto}")

    # Check for TCP
    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        print(f"Source Port    : {tcp_layer.sport}")
        print(f"Destination Port: {tcp_layer.dport}")
        print("Protocol       : TCP")

    # Check for UDP
    elif packet.haslayer(UDP):
        udp_layer = packet[UDP]
        print(f"Source Port    : {udp_layer.sport}")
        print(f"Destination Port: {udp_layer.dport}")
        print("Protocol       : UDP")

    # Check for Payload
    if packet.haslayer(Raw):
        payload = packet[Raw].load
        print(f"Payload        : {payload[:50]}")  # Show first 50 bytes

# Start sniffing packets
print("Starting packet capture... Press Ctrl+C to stop.")
sniff(prn=analyze_packet, count=10)
