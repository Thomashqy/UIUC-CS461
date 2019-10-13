import sys

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print('Need 2 files')
        sys.exit(1)

    with open(sys.argv[1]) as f:
        inputString = f.read().strip()
    inputBin = bin(int(inputString.decode('ascii').encode('hex'), 16))[2:]
    padding = len(inputBin) % 8
    for i in range(8 - padding):
    	inputBin = '0' + inputBin
    
    mask = 0x3FFFFFFF
    outputBytes = 0x00000000
    
    for index in range(0, len(inputBin), 8):
    	byte = int(inputBin[index:index+8], 2)
    	intermediate_value = ((byte ^ 0xCC) << 24) | ((byte ^ 0x33) << 16) | ((byte ^ 0xAA) << 8) | (byte ^ 0x55)
    	outputBytes = (outputBytes & mask) + (intermediate_value & mask)
    
    output = open(sys.argv[2], 'w')
    output.write(hex(outputBytes).rstrip('L'))
    output.close()
