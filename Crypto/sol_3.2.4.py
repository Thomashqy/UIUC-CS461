from fractions import gcd
from math import floor
import pbp
from Crypto.PublicKey import RSA



def prod(iterable):
	return reduce(lambda x, y: x*y, iterable, 1)



def productTree(X):
	result = [X]
	while len(X) > 1:
		X = [prod(X[i*2:(i+1)*2]) for i in range((len(X)+1)/2)]
		result.append(X)
	return result



def batchgcd_faster(X):
	prods = productTree(X)
	R = prods.pop()
	idx = 0
	while prods:
		print(idx)
		idx = idx + 1
		X = prods.pop()
		R = [R[int(floor(i/2))] % X[i]**2 for i in range(len(X))]
	return [gcd(r/n,n) for r,n in zip(R,X)]



def extended_euclidean_algorithm(a, b):
	if a == 0:
		return b, 0, 1
	else:
		g, y, x = extended_euclidean_algorithm(b % a, a)
		return g, x - (b // a) * y, y


def modular_inverse(e, r):
	g, x, y = extended_euclidean_algorithm(e, r)

	if g != 1:
		raise Exception('Modular inverse does not exist')
	else:
		return x % r



if __name__ == '__main__':
	modulus = []
	with open('moduli.hex') as f:
		modulus = f.read().splitlines()
	with open('3.2.4_ciphertext.enc.asc') as f:
		cipherText = f.read().strip()

	moduli = []
	for mod in modulus:
		moduli.append(int(mod, 16))

	a = batchgcd_faster(moduli)
	
	candidates = []
	for idx, prime in enumerate(a):
		if prime > 1:
			candidates.append([modulus[idx], (hex(prime).rstrip('L'))[2:]])
	
	plainText = ""
	for i in range(len(candidates)):
		n = int(candidates[i][0], 16)
		p = int(candidates[i][1].rstrip('L'), 16)
		q = n / p
		r = (p-1)*(q-1)
		e = 65537L
		d = 0L
		try:
			d = modular_inverse(e, r)
		except:
			continue
	
		key = RSA.construct((n, e, d, p, q))
		
		try:
			plainText = pbp.decrypt(key, cipherText)
			print(plainText)
		except:
			continue
	
	output = open('sol_3.2.4.txt', 'w')
	output.write(plainText)
	output.close()
