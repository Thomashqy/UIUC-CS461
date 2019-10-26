from scapy.all import *

import sys

def debug(s):
	print('#{0}'.format(s))
	sys.stdout.flush()

if __name__ == "__main__":
	conf.iface = sys.argv[1]
	ip_addr = sys.argv[2]
	
	my_ip = get_if_addr(sys.argv[1])
	src_port = RandShort()
	
	# SYN scan
	print('\n# Start scanning')
	for port in range(1, 1025):
		pkt = sr1(IP(dst=ip_addr)/TCP(sport=src_port, dport=port, flags="S"), timeout=2, verbose=False)
		if(pkt is not None):
			if(pkt.haslayer(TCP)):
				if(pkt.getlayer(TCP).flags == 0x12):
					rst = sr(IP(dst=ip_addr)/TCP(sport=src_port, dport=port, flags="R"), timeout=2, verbose=False)
					print('{},{}'.format(ip_addr, port))
	print('# Finish scanning\n')
