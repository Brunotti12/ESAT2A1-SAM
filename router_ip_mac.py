import subprocess
import re

def get_router_ip_mac():
    try:
        result = subprocess.check_output("arp -n", shell=True).decode()
        i = 0
        while(i < len(result)):
            if(result[i + 91:i + 95] == '.1  '):
                return (result[i + 81: i + 93], result[i + 114:i + 131])
            i += 80
    except subprocess.CalledProcessError:
        return "failed to retrieve table"
