#!/usr/bin/env python
import subprocess
import optparse
import re

def get_values():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Interface to change its MAC  address ------ 5H4D0W-R007 -------")
    parser.add_option("-m", "--mac", dest="new_mac", help="New MAC  address ------ 5H4D0W-R007 -------")
    (values, attributes) = parser.parse_args()
    if not values.interface and not values.new_mac:
        parser.error("[-] use --help for more info")
    if not values.interface:
        parser.error("[-] Please specify an interface, use --help for more info")
    if not values.new_mac:
        parser.error("[-] Please specify a MAC address, use --help for more info")
    return values

def mac_changer(interface, new_mac):
    print("[+] Changing MAC of " + interface + " to " + new_mac + "...")

    ###############################################
    #                                             #
    #     Vulnerable to Command Injection         #
    #                                             #
    ###############################################

    # print("ifconfig "+interface+" down")
    # subprocess.call("ifconfig "+interface +" down",shell=True)
    # subprocess.call("ifconfig "+interface+ " hw ether "+new_mac,shell=True)
    # subprocess.call("ifconfig "+interface+" up",shell=True)

    ###############################################
    #                                             #
    #                  Safer Code                 #
    #                                             #
    ###############################################

    subprocess.call(["ifconfig", interface, "down"])
    subprocess.call(["ifconfig", interface, "hw", "ether", new_mac])
    subprocess.call(["ifconfig", interface, "up"])

    print("[+] MAC address changed successfully!")

def get_current_mac(interface):
    ifconfig_result = subprocess.check_output(["ifconfig", interface])
    #print(type(str(ifconfig_result)))
    current_mac = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", str(ifconfig_result))  # convert byte type to string for comparison

    if current_mac:
        return current_mac.group(0)
    else:
        print("[-] Can`t find any MAC address")


#interface = input("Enter Interface > ")
#new_mac = input("Enter New MAC > ")

values = get_values()
interface = values.interface
new_mac = values.new_mac
current_mac = get_current_mac(interface)
print("Current MAC Address: " + str(current_mac))  # converting to string so as to deal with non-zero exit status
mac_changer(interface,new_mac)
#after changing the mac
current_mac = get_current_mac(interface)
if current_mac == new_mac:
    print("[+] MAC changed to " + new_mac)
else:
    print("[-] MAC didn't change")



