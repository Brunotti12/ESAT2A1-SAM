from scapy.all import ARP, Ether, srp

#function that gets the mac adress of a certain ip adress
def get_mac(ip):
    arp_request = ARP(pdst=ip)
    ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether_frame / arp_request
    result = srp(packet, timeout=2, verbose=False)[0]
    return result[0][1].hwsrc
