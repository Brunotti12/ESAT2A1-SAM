from MITM import MITM_attack
import multiprocessing

e = multiprocessing.Event()

MITM_attack(e)
