Client : Client.cc
	gcc -ggdb -w Client.cc -lssl -lcrypto -o client
Server : Server.cc	
	gcc -ggdb -w Server.cc -lssl -lcrypto -o server
clean : 
	rm client
	rm server
