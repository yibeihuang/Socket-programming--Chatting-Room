------------------------------- Description -----------------------------------

This chat-room application contains 3 files:

user_pass.txt: stores information of registered users and their related password. The password is stored using SHA1 hash function.

Server.py: Code for the server side. Server is constructed by multi-threading. The main thread is to accept new connection and I override ‘thread’ class with ‘client_handler’ for every client connecting in. Server allow client to send commands including:’who’, ‘broadcast’, ‘send’, ‘last’, ‘chatrecord’, ‘invisible’, ‘logout’
If ‘ctrl +c’ is pressed, server will exit gracefully. If a client is inactive for TIME_OUT seconds, server will log it out forcefully.

Client.py: Code for the client side. Client can send command to server and receive data from server, it has the same mechanism for ‘ctrl+c’.

-------------------------------Development Environment-------------------------

Mac OS:10.10.5
Python:2.7.11
------------------------------- Instruction -----------------------------------

To run the program:
       1. Change directory to your files location, open the server in Mac terminal(or IDE like PyCharm). Type “python server.py”. If the port is occupied, the server will remind you by saying 'This port is being used’.    
       2. Open the client with the terminal. Type “python client.py”.
       3. Follow the program command. Input username then input password. Then terminal will display “you have logged in” indicates that you have logged in.
       4. Input the commands related arguments if exist.
       5. Log out the user by typing ‘logout’ or CTRL+C
       6. Terminates the server by typing CTRL+C 
		
------------------------------- Basic Command ---------------------------------
	
       who                       Displays name of other connected users that are visible

       last <number>                   Displays name of those users connected within the last <number> minutes. Let 0 < number < 60

       broadcast <message> 	          Sends <message> to all the online users 
					  (except those users who have been blocked)

       send <user> <message>           Send private <message> to a <user>
	 				   
       send (<user> <user> ...    Send <message> to the list of users
       <user>) message 

	logout                              Log out this user. 					
------------------------------- Additional function  ---------------------------------

       1. chatrecord: show all the chat record related to this user
       2. invisible: make the user invisible to other users, so that when another user command ‘who’, the invisible users will not be in the list
       3. visible: make the user visible to other users
------------------------------- Additional Command -------------------	
       chatrecord                    show the chatting record of the user

       invisible                     make the user invisible to other users 

       visible                       make the user visible to other users 

       