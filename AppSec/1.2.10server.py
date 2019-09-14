#!/usr/bin/env python
import socket

def main():
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.bind(('127.0.0.1', 31337))
	s.listen(1)
	while True:
		c, addr = s.accept()
		print("Connection Successful")
		break

if __name__ == '__main__':
	main()
