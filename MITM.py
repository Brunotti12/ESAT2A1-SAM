import time



def MITM_attack():
    try:
        #setup code
        while True:
            #code die zich moet blijven herhalen
            time.sleep(2)
    except KeyboardInterrupt:
        #code die alles hersteld (als deze nodig is)
        print("\nMITM attack terminated")
    return None
