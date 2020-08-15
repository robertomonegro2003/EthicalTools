#!usr/bin/env python
import os
os.sys.path.append('/usr/local/lib/python2.7/site-packages')
import scapy.all as scapy
import argparse # successor of optparse [deprecated]

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--ip", dest = "targetip", help = "Enter target IP/IP Range ------ 5H4D0W-R007 -------")
    values = parser.parse_args()
    if not values.targetip:
        parser.error("[-] Please specify an IP Address, use --help for more info")
    return values

def scanner(ip):
    #scapy.arping(ip)   -> arp requests directed to broadcast MAC

    arp_request = scapy.ARP(pdst = ip)   # 1. set IP to pdst field in ARP Class
    #scapy.ls(scapy.ARP())
    #arp_request.show()
    broadcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")          # 2. set destination MAC to broadcast MAC in Ether Class
    #scapy.ls(scapy.Ether())
    #broadcast.show()
    arp_request_broadcast = broadcast/arp_request  # combining frames
    #arp_request_broadcast.show()
    #print(arp_request.summary())
    #  srp() returns 2 lists, answered & unanswered
    answered_summary, unanswered_summary = scapy.srp(arp_request_broadcast, timeout = 1, verbose = False) #remove extra details
    #print(answered_summary.summary())

    results_list = []  # list of dictionaries
    for i in answered_summary:
        #print(i[1].psrc + "\t\t\t" + i[1].hwsrc) Source IP and MAC from 1st element of answered list
        results_dict = {"ip":i[1].psrc, "mac":i[1].hwsrc}  # a dictionary with ip and mac as keys
        results_list.append(results_dict)

    return results_list

def result(result_list):
    print("----------------------------------------------------")
    print("IP Address\t\t\tMAC Address")
    print("----------------------------------------------------")
    for client in result_list:
        print(client["ip"] + "\t\t\t" + client["mac"])

option = get_args()
scan_result = scanner(option.targetip)
result(scan_result)
