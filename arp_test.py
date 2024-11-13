from ARPpoisoning import ARP_poison
import multiprocessing

e = multiprocessing.Event()

ARP_poison(e)
