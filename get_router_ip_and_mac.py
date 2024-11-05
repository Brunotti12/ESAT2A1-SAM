import subprocess
import re

#geeft terug: tuple(ip, mac) van de router
def router_ip_mac():
    try:
        result = subprocess.check_output("arp -a", shell=True).decode()
        ip = result[20:32] #om dit te finetunen hebben we de naam van de raspberry pi nodig
        message = re.search(rf" at ", result)
        index = message.span()[1]
        router_mac = result[index: index + 17]
        return (ip, router_mac)
    except subprocess.CalledProcessError:
        return "Failed"
    
mac = router_ip_mac()
print(mac[1])
