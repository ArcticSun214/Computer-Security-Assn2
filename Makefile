Client : Client.cc
	gcc -ggdb Client.cc -lssl -lcrypto -o client

clean : 
	rm client
