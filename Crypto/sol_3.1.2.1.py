import sys
from string import ascii_uppercase

if __name__ == '__main__':
    if len(sys.argv) != 4:
        print('Need 3 files')
        sys.exit(1)

    with open(sys.argv[1]) as f:
        cipherText = f.read().strip()
    with open(sys.argv[2]) as f:
        key = f.read().strip()

    alphabets = ascii_uppercase
    cipherText = list(cipherText)
    plainText = ""
    for index in range(len(cipherText)):
        if cipherText[index].isalpha():
            toPlain = key.find(cipherText[index])
            plainText += alphabets[toPlain]
        else:
            plainText += cipherText[index]

    output = open(sys.argv[3], 'w')
    output.write(plainText)
    output.close()