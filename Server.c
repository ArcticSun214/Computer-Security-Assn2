#include <stdio.h>
#include <stdlib.h>
//#include <cstring>
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

/* Sets the Diffie-Hellman parameter. This is required to use the Anonymous
 * Diffie-Hellman cipher suite.
*/
void set_DH_param(SSL_CTX * openssl_context)
{
     DH *privkey;
     if((privkey = DH_new()) == NULL)
        printf("Creating DH private key failed");
     if(DH_generate_parameters_ex(privkey, 8, DH_GENERATOR_2, NULL) != 1)
         printf("Generating DH parameters failed");         
     SSL_CTX_set_tmp_dh(openssl_context, privkey);
}

void  authenticate(SSL *openssl_SSL)
{
    //Read in size of random number sent by client
    unsigned char numSize = 0;
    SSL_read(openssl_SSL,&numSize, sizeof(char));
    printf("HOLA:%u\n",numSize);

    //Receive encrypted random number
    unsigned char num[numSize];
    int size = SSL_read(openssl_SSL,&num, sizeof(num));
    printf("Size: %u \n",size);

    //Decrypt ecrypted random number
    unsigned char num_decrypt[numSize];
    FILE *fp = fopen("./mycert.pem","rb");
    if(fp == NULL)
    {
        printf("Failed to open \"mycert.pem\"");
    }

    RSA *rsa = RSA_new();
    rsa = PEM_read_RSAPrivateKey(fp, &rsa, NULL, NULL);
    if(rsa == NULL)
        printf("RSAPrivatekey failed\n");
    if(RSA_private_decrypt(sizeof(num), num,num_decrypt,rsa,\
        RSA_PKCS1_PADDING) < 0)
    {
        printf("Failed to decrypt random number");
    }

    
}

/* A function used in debugging to output SSL error
*/
void getError(int err)
{
    //err = SSL_get_error(openssl_SSL,err);
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

    //Handle Inputs
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



    //Create context
    openssl_context = SSL_CTX_new(SSLv3_server_method());
    if(openssl_context == NULL)
    {
        printf("SSL_CTX_new() Failed");
    }

    //Set the Diffie-Hellman Parameters
    set_DH_param(openssl_context);

    //Set the cipher suites to be used
    if( SSL_CTX_set_cipher_list(openssl_context, "aNULL") != 1)
    {
	    printf("SSL_CTX_set_cipher_list() Failed"); 
    }
    
    //Set the certificate
    if(SSL_CTX_use_certificate_file(openssl_context,"mycert.pem",\
        SSL_FILETYPE_PEM) !=1)
    {
        printf("SSL_CTX_use_certificate_file() Failed");
    }

    //Set the RSA private Key
    if(SSL_CTX_use_PrivateKey_file(openssl_context,"mycert.pem",\
        SSL_FILETYPE_PEM) != 1)
    {
        printf("SSL_CTX_use_PrivateKey_file() Failed");
    }

    //Create SSL
    openssl_SSL = SSL_new(openssl_context);
    if(openssl_SSL== NULL)
    {
        printf("SSL_new");
    }
    SSL_set_fd(openssl_SSL, newsockfd);
    SSL_set_accept_state(openssl_SSL);


    //Accept SSL 
    int err = SSL_accept(openssl_SSL);
    if (err < 0)
    {
        printf("SSL_accept failure");
    }

    //Hand Action
    //Authenticate

    authenticate(openssl_SSL);
    printf("DD");

    
    SSL_shutdown(openssl_SSL);


	
    return 0;
}
