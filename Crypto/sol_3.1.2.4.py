import sys

if __name__ == '__main__':
    if len(sys.argv) != 5:
        print('Need 4 files')
        sys.exit(1)

    with open(sys.argv[1]) as f:
        cipherText = f.read().strip()
    with open(sys.argv[2]) as f:
        dkey = f.read().strip()
    with open(sys.argv[3]) as f:
        modulo = f.read().strip()
	
	cipherText = long(cipherText, 16)
	dkey = long(dkey, 16)
	modulo = long(modulo, 16)
    
	plainText = hex((cipherText ** dkey) % modulo)[2:].rstrip('L')
	print(plainText)
	
    output = open(sys.argv[4], 'w')
    output.write(plainText)
    output.close()
