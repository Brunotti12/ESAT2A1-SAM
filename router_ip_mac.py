from scapy.all import ARP, Ether, srp
import subprocess

def get_router_ip():
    try:
        result = subprocess.check_output("arp -n", shell=True).decode()

        for i in result.splitlines():
            for j in i.split():
                if j[-2:] == '.1':
                    return j
    except subprocess.CalledProcessError:
        return "couldn't fetch arp table"

def get_mac(ip):
    arp_request = ARP(pdst=ip)
    ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether_frame / arp_request
    result = srp(packet, timeout=2, verboes=False)[0]
    return result[0][1].hwsrc
