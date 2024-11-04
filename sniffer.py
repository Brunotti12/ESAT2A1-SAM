from scapy.all import *
import struct
import binascii

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

def wep_decrypt(packet):
    wep_key = bytes.fromhex("0000000000")

    #print("found one")

    if packet.haslayer(Dot11WEP):
        iv = packet[Dot11WEP].iv

        rc4_key = iv + wep_key
        encrypted_payload = packet[Dot11WEP].wepdata

        decrypted_data = rc4(rc4_key, encrypted_payload)

        data, icv = decrypted_data[:-4], decrypted_data[-4:]

        calculated_icv = struct.pack('<L', binascii.crc32(data) & 0xFFFFFFFFFF)
        print(icv, calculated_icv)

        if icv == calculated_icv:
            print("Decrypted Packet: ", data)
        else:
            print("ICV mismatch, possible decryption failure.")
    else:
        print("no wep")


def packet_filter(packet):
    router_mac = '08:be:ac:03:dc:2e'
    if packet.haslayer(Dot11):
        return (packet.addr1 == router_mac or packet.addr2 == router_mac)
    return False

sniff(iface = 'wlan0mon', prn = wep_decrypt, lfilter = packet_filter, count = 100)
