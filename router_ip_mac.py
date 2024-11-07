import subprocess
import re

def get_router_ip_mac():
    try:
        result = subprocess.check_output("arp -a", shell=True).decode()
        index = re.search(rf"edimax.setup ", result).span()[1] #vul de naam van het toestel in ipv Zenbook.mshome.net 
        router_ip = result[index + 1: index + 13]
        router_mac = result[index + 18: index + 35]
        return (router_ip, router_mac)
    except subprocess.CalledProcessError:
        return "Failed"
    except AttributeError:
        return "Wrong device name"
