#This is a test file for the get_route_ip.py file

import router_ip_mac
print("Router ip = ", router_ip_mac.get_router_ip())

try:
    ip = input("Geef het ip adress: ")
    print("MAC address: ", router_ip_mac.get_mac(ip))
except KeyboardInterrupt:
    print("\nTerminated")
