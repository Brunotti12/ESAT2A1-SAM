import multiprocessing
import multiprocessing.process
from ARPpoison import ARP_poison
from MITM import MITM_attack

try:
    start_mitm_event = multiprocessing.Event()

    arp_poison = multiprocessing.Process(target=ARP_poison, args=(start_mitm_event,))
    arp_poison.start()

    start_mitm_event.wait()

    mitm_attack = multiprocessing.Process(target=MITM_attack)
    mitm_attack.start



except KeyboardInterrupt:
    mitm_attack.terminate()
    arp_poison.terminate()
    print("\nAll processes terminated")
