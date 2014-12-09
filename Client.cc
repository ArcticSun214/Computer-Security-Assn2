#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/err.h>

//SSL_library_init();

/* Global variables used throughout the program
*/
char *serverAddress;
char *port;
char *action;
char *file;



/* Checks if the input is valid. This function gets the arugments passed into
 * the executable. It checks whether the number of arguments passed in is
 * correct and whehter it is in the right format
*/
void validateInput(int argc, char *argv[])
{
    //Check if number of arguments is correct
    if(argc != 5)
    {
        printf("Invalid Argument\n");
        printf("Argument Format is: client --serverAddress=xxx.xxx.xxx.xxx" 
            "--port=xxxx --[send | receive] ./<file>\n");
        exit(EXIT_FAILURE);
    }
    else
    {
        printf("Argument is valid\n");
    }
}

/*This function gets the arguments passed into the executable. It parses the
 * arguments to get the serverAddress, port, and send or receive action. 
*/
void getInput(int argc, char *argv[])
{
 
	//Get server address
   	serverAddress = argv[1]+16; // The actual server address is offset by 
                               // "--serverAddress=" which is 16 char long
   	printf(serverAddress);
   	printf("\n");

   	//Get port
    port = argv[2] + 7; //The acutal port is offset by "--port=" which is 7
                       //char long
    printf(port);
    printf("\n");

    //Get Action
    action = argv[3] + 2;   //The actual action is offset by "--" which is 2
                           //char long
    printf(action);
    printf("\n");

    //Get File
    file = argv[4];
    printf(file);
    printf("\n"); 
}

/*Converts the string representation of port into its unsigned short
 *representation. This is done by getting the string digit and subtracting 48 to
 get the decimal value. I then multiply it by a power of 10 to shift it to its
 right position.
*/ 
unsigned short convertPort(char port[4])
{
    unsigned short sPort = 0;
    //get first digit
    sPort += (port[0] - 48) * 1000;
    //get second digit
    sPort += (port[1] - 48) * 100;
    //get third digit
    sPort += (port[2] - 48) * 10;
    //get fourth digit
    sPort += (port[3] - 48) * 1;

    printf("%u",sPort);
    return sPort;
}

int main(int argc, char *argv[])
{
    int sockfd;
    struct sockaddr_in server_addr;
    struct hostent *he;

    SSL_CTX *openssl_context;
    SSL *openssl_SSL;

    validateInput(argc,argv);
    getInput(argc,argv);

    //Initialize Input
    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();

    //Initialize socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd < 0)
    {
        printf("Failed at socket");
        exit(EXIT_FAILURE);
    }


    //Initialize server_addr
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(convertPort(port));
    if ((he=gethostbyname(serverAddress)) == NULL)
    {
        printf("Hostname Error");
        exit(EXIT_FAILURE);
    }
    server_addr.sin_addr = *((struct in_addr *)he->h_addr);
    bzero(&(server_addr.sin_zero),8);

    //SERVER DIFFERS HERE

    //Connect
    if(connect(sockfd, (struct sockaddr *) &server_addr, sizeof(struct
        sockaddr)) < 0)
    {
        printf("Connect Error");
        exit(EXIT_FAILURE);
    }
    else
    {
        printf("Connect Successful");
    }

    openssl_context = SSL_CTX_new(SSLv3_client_method());
    if(SSL_CTX_set_cipher_list(openssl_context, "ALL") != 1)
        printf("SET CIPHER\n\n");
    if(openssl_context == NULL)
        printf("new context fail");
    
    openssl_SSL = SSL_new(openssl_context);
    if(openssl_SSL == NULL)
        printf("new ssl fail");
    SSL_set_fd(openssl_SSL, sockfd);
    if(SSL_connect(openssl_SSL) < 0)
    {
        printf("SSL_Connect() failed");
    }
    else
    {
        printf("SSL_Connect() success");
    }
    char hi[] = "hi";
    SSL_write(openssl_SSL,hi,strlen(hi));
    printf("DD"); 

    SSL_shutdown(openssl_SSL);


	
    return 0;
}
