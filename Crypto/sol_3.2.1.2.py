import sys
from pymd5 import md5, padding
import urllib

if __name__ == '__main__':
	if len(sys.argv) != 4:
		print('Need 3 files')
		sys.exit(1)

	with open(sys.argv[1]) as f:
		query = f.read().strip()
	with open(sys.argv[2]) as f:
		command = f.read().strip()

	token = query[:query.find("=")+1]
	currentHash = query[query.find("=")+1:query.find("&")]
	msg = query[query.find("&")+1:]

	length = len(msg) + 8
	bits = (length + len(padding(length*8)))*8

	h = md5(state=currentHash.decode("hex"), count=bits)
	h.update(command)

	newHash = h.hexdigest()
	padding = urllib.quote(padding(length*8))
	msg = msg + padding + command

	newQuery = token + newHash + "&" + msg

	output = open(sys.argv[3], 'w')
	output.write(newQuery)
	output.close()
