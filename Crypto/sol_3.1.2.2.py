import sys
from Crypto.Cipher import AES

if __name__ == '__main__':
    if len(sys.argv) != 5:
        print('Need 4 files')
        sys.exit(1)

    with open(sys.argv[1]) as f:
        cipherText = f.read().strip()
    with open(sys.argv[2]) as f:
        key = f.read().strip()
    with open(sys.argv[3]) as f:
        iv = f.read().strip()
	
	cipherText = cipherText.decode('hex')
	key = key.decode('hex')
	iv = iv.decode('hex')
    
	aes = AES.new(key, AES.MODE_CBC, iv)
	plainText = aes.decrypt(cipherText)
	
    output = open(sys.argv[4], 'w')
    output.write(plainText)
    output.close()
