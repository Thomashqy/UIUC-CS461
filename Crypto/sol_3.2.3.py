from Crypto.Cipher import AES
from Crypto import Random
from binascii import hexlify
import urllib2, sys



def get_status(u):
	req = urllib2.Request(u)
	try:
		f = urllib2.urlopen(req)
		print(f.code)
	except urllib2.HTTPError, e:
		if e.code == 404:
			return 'found'
		else:
			return None



if __name__ == '__main__':
	if len(sys.argv) != 3:
		print('Need 2 file')
		sys.exit(1)
	
	with open(sys.argv[1]) as f:
		cipherText = f.read().strip()
	cipherText = bytearray(cipherText.decode('hex'))
	
	result = []
	for block in range(0, len(cipherText), 16):
		prev_cipherText = cipherText[block:block + 16]
		current_block = cipherText[block + 16:block + 32]
		print(block)

		guesses = []
		for index in range(1, 17):
			byte_of_first_block = prev_cipherText[-index]
			for guess in range(256):
				prev_cipherText[-index] = byte_of_first_block ^ guess ^ 16
				fake_cipher = hexlify(prev_cipherText) + hexlify(current_block)
				if get_status('http://cs461-mp3.sprai.org:8081/mp3/yhyuan2/?' + fake_cipher) == 'found':
					guesses.append(guess)
					print(chr(guess))
					for i in range(-1, -index-1, -1):
						prev_cipherText[i] = cipherText[block+16+i] ^ guesses[-i-1] ^ (15 - index - i)
					break
		guesses.reverse()
		for i in range(len(guesses)):
			result.append(guesses[i])
	
	result = [chr(result[i]) for i in range(len(result))]
	
	plainText = ""
	for i in range(len(result)):
		if result[i] == chr(0x10):
			break
		plainText += result[i]
	print(plainText)
	
	output = open(sys.argv[2], 'w')
	output.write(plainText)
	output.close()
