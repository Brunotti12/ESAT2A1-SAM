import subprocess
import re

def get_router_ip_mac():
    # Step 1: Run 'arp -a' to get the ARP table
    try:
        result = subprocess.check_output("arp -a", shell=True).decode()
    except subprocess.CalledProcessError:
        return "Failed to retrieve ARP table."

    # Step 2: Extract IP addresses and their corresponding MAC addresses
    arp_entries = {}
    for line in result.splitlines():
        match = re.match(r"([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\s+(([a-f0-9]{2}:){5}[a-f0-9]{2})", line)
        if match:
            ip = match.group(1)
            mac = match.group(2)
            arp_entries[ip] = mac

    # Step 3: Find the router IP (typically ending with .1)
    router_ip = None
    for ip in arp_entries:
        if ip.endswith(".1"):
            router_ip = ip
            router_mac = arp_entries[ip]
            print(f"Found router IP: {router_ip}, MAC: {router_mac}")
            break

    if not router_ip:
        return "Router not found in ARP table."

    # Step 4: Verify the MAC address of the router
    # If we have the router IP but want to verify its MAC address, we can ping it.
    try:
        subprocess.check_output(f"ping -c 1 {router_ip}", shell=True)
        return f"Router IP: {router_ip}, MAC: {router_mac}"
    except subprocess.CalledProcessError:
        return "Router is unreachable or not responding."
