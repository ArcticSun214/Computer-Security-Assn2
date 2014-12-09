#include <stdio.h>
#include <stdlib.h>
#include <cstring>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/bio.h>
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
    if(argc != 2)
    {
        printf("Invalid Argument\n");
        printf("Argument Format is: server --port=xxxx\n");
        exit(EXIT_FAILURE);
    }
    else
    {
        printf("Argument is valid\n");
    }
}

/*This function gets the arguments passed into the executable. It parses the
 * arguments to get the port. 
*/
void getInput(int argc, char *argv[])
{
   	//Get port
    port = argv[1] + 7; //The acutal port is offset by "--port=" which is 7
                       //char long
    printf(port);
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
    int sockfd, newsockfd;
    struct sockaddr_in server_addr;
    struct sockaddr_in client_addr;
    struct hostent *he;
	size_t size;

    SSL_CTX *openssl_context;
    SSL *openssl_SSL;

    validateInput(argc,argv);
    getInput(argc,argv);

    //Initialize Input
    SSL_load_error_strings();
    SSL_library_init();
	ERR_load_crypto_strings();
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
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    bzero(&(server_addr.sin_zero),8);

    //SERVER DIFFERS HERE
    //Bind
    if((bind(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr))) < 0)
    {
        printf("Bind Error");
        exit(EXIT_FAILURE);
    }

    //Listen
    if((listen(sockfd,5)) < 0)
    {
        printf("Listen Error");
        exit(EXIT_FAILURE);
    }

    //Accept
    size = sizeof(client_addr);
    newsockfd = accept(sockfd, (struct sockaddr *) &client_addr, &size); 
    if (newsockfd < 0)
        printf("Accept failure");
    else
        printf("Accept success");

    openssl_context = SSL_CTX_new(SSLv3_server_method());
    if(openssl_context == NULL)
        printf("context failed");
if( SSL_CTX_set_cipher_list(openssl_context, "ALL") != 1)
	printf("CIPHER\n\n");
int i = SSL_CTX_use_certificate_file(openssl_context,"mycert.pem",SSL_FILETYPE_PEM);
int b = SSL_CTX_use_PrivateKey_file(openssl_context,"mycert.pem",SSL_FILETYPE_PEM);
if (i !=1)
printf("DSF\n\n");
	ERR_print_errors_fp(stdout);
if( b!=1 )
printf("DSDFFF\n\n");
    openssl_SSL = SSL_new(openssl_context);
    if(openssl_SSL== NULL)
        printf("SSL_nes");
    SSL_set_fd(openssl_SSL, newsockfd);
SSL_set_accept_state(openssl_SSL);
    int err = SSL_accept(openssl_SSL);

    if (err < 0)
    {
        printf("SSL_accept failure");
    }
    err = SSL_get_error(openssl_SSL,err);
    switch (err)
    {
        case SSL_ERROR_NONE:
            printf("1");
            break;
        case SSL_ERROR_ZERO_RETURN:
            printf("2");
            break;
        case SSL_ERROR_WANT_READ:
            printf("3");
            break;
        case SSL_ERROR_WANT_WRITE:
            printf("4");
            break;
        case SSL_ERROR_WANT_CONNECT:
            printf("5");
            break;
        case SSL_ERROR_WANT_ACCEPT:
            printf("6");
            break;
        case SSL_ERROR_WANT_X509_LOOKUP:
            printf("7");
            break;
        case SSL_ERROR_SYSCALL:
            printf("8");
            break;
        case SSL_ERROR_SSL:
            printf("9");
            break;
	default:
	    printf("DEF");
        break;
    }
	ERR_print_errors_fp(stdout);
	ERR_get_error();
char buf[1024];
SSL_read(openssl_SSL,buf, strlen(buf));
printf(buf);
printf("DD");
    SSL_shutdown(openssl_SSL);


	
    return 0;
}
