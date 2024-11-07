import subprocess
import re

def get_router_ip():
    try:
        result = subprocess.check_output("arp -n", shell=True).decode()

        for i in result.splitlines():
            for j in i.split():
                if j[-2:] == '.1':
                    return j
    except subprocess.CalledProcessError:
        return "couldn't fetch arp table"
