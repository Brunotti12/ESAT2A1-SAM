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

    mitm_attack.join()
    arp_poison.join()

except KeyboardInterrupt:
    mitm_attack.terminate()
    mitm_attack.join()
    arp_poison.terminate()
    arp_poison.join()
    print("\nAll processes terminated")
