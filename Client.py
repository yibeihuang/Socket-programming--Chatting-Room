#!/usr/bin/python           # This is Client.py file
#Author: Yibei
from socket import *			 # Import socket module
import hashlib
import signal,select
import sys

def exit_gracefully(signum, frame):
    # restore the original signal handler as otherwise evil things will happen
    # in raw_input when CTRL+C is pressed, and our signal handler is not re-entrant
	signal.signal(signal.SIGINT, original_sigint)
	try:
		if raw_input("\nReally quit? (y/n)> ").lower().startswith('y'):
			clientSocket.send('logout')
			sys.exit(1)
	except KeyboardInterrupt:
		print("Ok ok, quitting")
		clientSocket.send('log_out')
		clientSocket.close()	#close the socket connection
		sys.exit(1)
	# restore the exit gracefully handler here    
	#signal.signal(signal.SIGINT, exit_gracefully)

if __name__ == '__main__':
	# store the original SIGINT handler
	original_sigint = signal.getsignal(signal.SIGINT)
	signal.signal(signal.SIGINT, exit_gracefully)

	serverName = 'localhost'      #specify the server name to be connected
	serverPort = 12345				#specify the port of the server
	clientSocket = socket(AF_INET, SOCK_STREAM)			 # Create a socket object
	try:	
		clientSocket.connect((serverName, serverPort))		#connect to the server
		print 'successfully connected, you can send message now'
		while True:
			# Wait for file descriptor raise a event
			try:
				read_sockets= select.select([sys.stdin, clientSocket], [], [])[0]
			except:    #do cleanup
				clientSocket.sendall(b'close')     #'close' is the hint for server that it should close
				clientSocket.close()
				sys.exit()
			for sock in read_sockets:
				#incoming message from remote server
				if sock == clientSocket:
					data = sock.recv(1024).decode()
					if not data:
						print('\nDisconnected from server')
						clientSocket.sendall(b'close')
						clientSocket.close()
						sys.exit()
					else:
				        #print data without adding a '\n'    
						sys.stdout.write(data)
						sys.stdout.flush()	
				else:
					message = (raw_input()).encode()
					clientSocket.send(message)
	except:
		#print 'connection failed'
		sys.exit()

	#clientSocket.close() #??seems useless