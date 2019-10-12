import sys
from Crypto.Hash import SHA256

if __name__ == '__main__':
    if len(sys.argv) != 4:
        print('Need 3 files')
        sys.exit(1)

    with open(sys.argv[1]) as f:
        firFile = f.read().strip()
    with open(sys.argv[2]) as f:
        secFile = f.read().strip()
    
    h1 = SHA256.new(firFile.decode('ascii'))
    firHash = h1.hexdigest()
    firHash = bin(int(firHash, 16))[2:]
    
    h2 = SHA256.new(secFile.decode('ascii'))
    secHash = h2.hexdigest()
    secHash = bin(int(secHash, 16))[2:]
    
    distance = 0
    for index in range(len(firHash)):
    	if firHash[index] == secHash[index]:
    		distance += 1
	
    output = open(sys.argv[3], 'w')
    output.write(hex(distance)[2:])
    output.close()
