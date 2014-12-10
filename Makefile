Client : Client.c
	gcc -ggdb -w Client.c -lssl -lcrypto -o client
Server : Server.c
	gcc -ggdb -w Server.c -lssl -lcrypto -o server
clean : 
	rm client
	rm server
