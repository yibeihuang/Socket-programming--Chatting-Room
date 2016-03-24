#!/usr/bin/python           # This is Server.py file
#Author: Yibei
from socket import *  # Import socket module
import signal
import sys, os, re
import mmap, threading, select, hashlib
import time

os.environ['BLOCK_TIME'] = '60'  # environment variable
os.environ['TIME_OUT'] = '5'
logout_time = {}  # record the time of last logout for each user in a dictionary
loggedin = []  # record all the users that is logged in
threads = []
loggedusername = []
passbook = {}  # recors all users and corresponding password
block_user = {}  # record the users blocked
with open('user_pass.txt', 'r') as f:
	for line in f:
		splitLine = line.split()
		passbook[splitLine[0]] = splitLine[1]
chatrecord = {}  # show chatting record
for username in passbook:
	chatrecord[username] = ''
TIME_OUT = int(os.environ.get('TIME_OUT'))
BLOCK_TIME = int(os.environ.get('BLOCK_TIME'))


class client_handler(threading.Thread):
	def __init__(self, sock, addr):
		threading.Thread.__init__(self)
		self.sock = sock
		self.addr = addr
		self.last_checkin = time.time()  # checkin the last time user send data
		self.Login = False
		self.invisible = False
		self.username = ''
		self.timeout = False
		self.invalid = False

	def get_data(self):	# either return data or FALSE which stand for read time-out
		while True:
			try:
				data = self.sock.recv(1024)
				if not data:
					continue
				else:
					self.last_checkin = time.time()  # if successfully get data, update the time of last_checkin
					return data
			except:
				if time.time() - self.last_checkin > TIME_OUT: # if a client is inactive for 30 minutes, the server should automatically log this user out
					self.hdlr_log_out()
					self.timeout = True
					return False	#return false when time_out occurs, upper level should quit

	def login(self):
		# if self.block == False:
		self.sock.send("Please input username:\n")
		username = self.get_data()
		if not username:
			return #stop the thread
		if username not in passbook:	#user not exists
			try:
				self.sock.send("invalid username\n")
			except:
				return -1	#critical, to stop the thread
			#self.hdlr_log_out()
			return -2	#username not exist
		#user blocked
		if username in block_user and self.addr[0] == block_user[username][0] and time.time() - block_user[username][1] < BLOCK_TIME:
			return
		#user already log in
		elif username in loggedusername:
			self.sock.send('you have already loged in\n')
			self.hdlr_log_out()
			return 
		else:
			for trytime in range(3):
				self.sock.send("Please input password:\n")
				password_client = self.get_data()
				hash_object = hashlib.sha1(password_client.encode('utf-8'))  # encrypt password to sha1
				hex_dig = hash_object.hexdigest()
				if hex_dig == passbook[username]:
					self.username = username
					logout_time[self.username] = None  # initialize the logout time of this user
					self.Login = True  # change the Login status of this user
					self.invalid = False
					loggedin.append(self)  # add record of this user to threads
					loggedusername.append(self.username)
					return True
			#self.hdlr_log_out() 
			block_user[username] = [self.addr[0], time.time()]
			print block_user[username][0]
			print block_user[username][1]
			return False

	def login_with_block(self):		
		self.sock.send("Login...\n")  # ??
		while True:
			if self.login() and self.invalid == True:
				return
			elif self.Login and self.invalid == False:
				self.sock.send('you have logged in\n')
				return
			#block_user[self.username] = [self.addr, time.time()]
			self.sock.send('you have been blocked\n')
			self.hdlr_log_out()

	# display names of other connected users
	def hdlr_who(self):
		users = ''
		for user in loggedin:
			if user.Login and user != self and user.invisible == False:
				users = users + user.username + ' '
		self.sock.send(users+'\n')

	# Displays name of those users connected within the last <number> minutes
	def hdlr_last(self, args):
		users = ''
		minutes = int(''.join(args))
		if minutes >=0:
			# seconds = 60*re.findall(r'<(.+?)>', args) # match all the text between <>            
			seconds = 60 * minutes
			if seconds >= 0 and seconds <= 3600:
				for user in loggedin:
					if user.Login and user != self and user.invisible == False:
						users += user.username + ' '
				for user in logout_time:
					if logout_time[user] and logout_time[user] > time.time() - seconds:
						users += user + ' '
				users += '\n'
				self.sock.send(users)
			else:
				self.sock.send('time out of range\n')
		else:
			self.sock.send('wrong arguments\n')

    # Broadcasts <message> to all connected users.
	def hdlr_broadcast(self, args):
		if args == None: #if only command
			self.sock.send('wrong arguments\n')
		else : #command + space + message
			message = ''.join(args)
			chatrecord[self.username]+=('broadcast: ' + message+'\n')
			for user in loggedin:
				if user.Login and user != self:
					user.sock.send(self.username + ' broadcast: ' + message+'\n')
					chatrecord[user.username]+=(self.username + ':broadcast ' + message+'\n')
			

	#send messages
	def hdlr_send(self, args):
		argstring = ''.join(args)
		if '(' in argstring.split(' ')[0]: #multiple users
			try:
				regex1 = re.compile('\((.*?)\)')
				m = regex1.search(argstring)
				username = m.groups()[0].split(' ') #extract users from argstring
				regex2 = '('+m.groups()[0]+')'
				message = re.sub(regex2,'',argstring).split(' ',1)[1] #extract message from argstring
			except:
				self.sock.send('wrong expression\n')
				return
		elif '(' not in argstring.split(' ')[0]: #private user
			username = argstring.split(' ', 1)[0]
			message = argstring.split(' ', 1)[1]
		else:
			self.sock.send('wrong arguments\n')
			return False
		chatrecord[self.username]+=('send:' + argstring+'\n')
		for user in loggedin:  #only thos who logged in can get the message
			if user.username in username:
				user.sock.send(self.username + ' send:' + message+'\n')
				chatrecord[user.username]+=(self.username + ' send:' + message+'\n')
    
    # Log out this user
	def hdlr_log_out(self):
		# record logout time with a dictionary
		# if the user is logged in
		if self.Login:
			logout_time[self.username] = time.time()
			loggedin.remove(self)
			threads.remove(self)
			self.Login = False
			loggedusername.remove(self.username)
		try:
			self.sock.send('you have been logged out\n')
		except:
			pass
		self.sock.shutdown(SHUT_WR)
		self.sock.close()
		# remove the user from threads

	def cmd_func(self, cmd, args):
		if cmd == 'who':
			return self.hdlr_who()
		elif cmd == 'last':
			return self.hdlr_last(args)
		elif cmd == 'broadcast':
			return self.hdlr_broadcast(args)
		elif cmd == 'send':
			return self.hdlr_send(args)
		elif cmd == 'logout':
			return self.hdlr_log_out()
		elif cmd == 'invisible':
			return self.hdlr_invisible()
		elif cmd == 'chatrecord':
			return self.hdlr_chatrecord()
		elif cmd == 'visible':
			return self.hdlr_visible()
		else:
			self.sock.send('command does not exist\n')

	def extract_cmd(self, data):
		print data, type(data)
		sp = data.split(' ', 1)    #upgrade to regex
		if len(sp) > 1:
			return sp[0], sp[1:]
		else:
			return sp[0], None

	def hdlr_invisible(self):  # make the user invisible to other users
		if not self.invisible:
			self.invisible = True
			self.sock.send('you are invisible now\n')
		else:
			self.sock.send('you are visible now\n')
	def hdlr_visible(self):
		if self.invisible:
			self.invisible = False
			self.sock.send('you are visible now\n')
		else:
			self.sock.send('you are visible now\n')

	def hdlr_chatrecord(self):  # show the chatting record of the user
		message = chatrecord[self.username]
		self.sock.send('chat record is: \n' + message+'\n')

	def cmd_handler(self):
		self.sock.send('Command:\n')
		data = self.get_data()

		cmd, args = self.extract_cmd(data)
		self.cmd_func(cmd, args)

	def run(self):
		self.login_with_block()
		while self.username == '':
			self.login_with_block()
		while self.Login:
			self.cmd_handler()


def exit_gracefully(signum, frame):
	# http://stackoverflow.com/questions/18114560/python-catch-ctrl-c-command-prompt-really-want-to-quit-y-n-resume-executi
	# restore the original signal handler as otherwise evil things will happen
	# in raw_input when CTRL+C is pressed, and our signal handler is not re-entrant
	signal.signal(signal.SIGINT, original_sigint)
	try:
		if raw_input("\nReally quit? (y/n)> ").lower().startswith('y'):
			sys.exit(1)
	except KeyboardInterrupt:
		print("Ok ok, quitting")
		sys.exit(1)


if __name__ == '__main__':

	original_sigint = signal.getsignal(signal.SIGINT)
	signal.signal(signal.SIGINT, exit_gracefully)  # trap keyboard interrupts

	serverPort = 12345  # Reserve a port for your service.
	serverSocket = socket(AF_INET, SOCK_STREAM)  # Create a socket object
	try:
		serverSocket.bind(('localhost', serverPort))
		serverSocket.listen(10)  # Now wait for client connection.
	except:
		print 'the port is being used'
		sys.exit()

	thread_objs = []

	def create_thread(connectionSocket, addr):
		current_client = client_handler(connectionSocket, addr)
		current_client.setDaemon(True)
		current_client.start()
		threads.append(current_client)

	while True:
		print 'wait for connection'
		connectionSocket, addr = serverSocket.accept()  # Establish connection with client.
		connectionSocket.setblocking(0) #set the socket to unblocking
		print addr, 'is connected'
		# Create new thread
		create_thread(connectionSocket, addr)



# kill a thread when log out/ a socket close
# kill a thread when client terminate the connection
# if a client press ctrl+c, how would the threads in the server side terminates correspondingly,

# http://blog.csdn.net/zhangzheng0413/article/details/41728869
