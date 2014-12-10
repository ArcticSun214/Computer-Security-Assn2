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
#include <openssl/rand.h>

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
    //gerrsecond digit
    sPort += (port[1] - 48) * 100;
    //get third digit
    sPort += (port[2] - 48) * 10;
    //get fourth digit
    sPort += (port[3] - 48) * 1;

    printf("%u",sPort);
    return sPort;
}



/* This function authenticates the server the client is trying to connect to
*/
int authenticateServer(SSL * openssl_SSL)
{
    //Create Rsa
    FILE *fp = fopen("./publicKey.pem","rb");
    if(fp == NULL)
    {
        printf("Failed to open file \"public.pem\"");
    }
    RSA *rsa = RSA_new(); 
    rsa=PEM_read_RSA_PUBKEY(fp, &rsa, NULL, NULL);
    fclose(fp);

    //Variables
    unsigned char number[RSA_size(rsa)-11];             //Random number to be encrypted
    unsigned char num_encrypt[RSA_size(rsa)];           //Encrypted Random Number

    //Generate random number;
    RAND_bytes(number, sizeof(number));
    
    //Encrypt number
    int t =RSA_public_encrypt(sizeof(number),number,num_encrypt,rsa,\
        RSA_PKCS1_PADDING);
    if(t < 0)
     {
         printf("Encryption of PRNG number Failed");
	ERR_print_errors_fp(stdout);
     }
     printf("i: %u \n", t);

    //send size of random num
     unsigned char numSize= sizeof(num_encrypt);
     SSL_write(openssl_SSL,&numSize,sizeof(numSize));

    // Send ecrypted random num
     int b = SSL_write(openssl_SSL,num_encrypt,sizeof(num_encrypt));
     printf("encrypted random size: %u \n\n",b);
     printf("pre_enc: %i \n",(int)number[0]);

     //Hashing
     unsigned char hashed[SHA_DIGEST_LENGTH];
     SHA1(number,sizeof(number), hashed);
     printf("HS: %u \n", (int)hashed[0]);
     
     
     //Read signed hashed value
     unsigned char signedHash_size = 0;
     SSL_read(openssl_SSL, &signedHash_size, sizeof(signedHash_size));
     unsigned char signedHash[signedHash_size];
     SSL_read(openssl_SSL, signedHash, sizeof(signedHash));

     //Verify signned hashed value
     unsigned char receivedHashed[SHA_DIGEST_LENGTH];
     if(RSA_verify(NID_sha1, number, sizeof(number), signedHash, sizeof(signedHash), \
         rsa) != 1) 
     {
         printf("Verification failed");
     }


    //Compare hashed and received hashed value
     int isAuthenticated = 1;
     int i = 0;
     int size = sizeof(receivedHashed);
     while( i < size)
     {
         if (receivedHashed[i] != hashed[i])
         {
             printf("%u \n",(unsigned int)receivedHashed[i]);
             printf("%u \n",(unsigned int)hashed[i]);
             printf("%i \n",i);
             return 0;  //Received Hash value does not matched. 
                        //Server is not Authenticated.
         }
         i++;
     }
    return 1;
}

int main(int argc, char *argv[])
{
    int sockfd;
    struct sockaddr_in server_addr;
    struct hostent *he;

    SSL_CTX *openssl_context;
    SSL *openssl_SSL;
   // ERR_print_errors_fp(stdout);

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

    //Create Context
    openssl_context = SSL_CTX_new(SSLv3_client_method());
    if(openssl_context == NULL)
    {
        printf("new context fail");
    }

    //Set Cipher Suites
    if(SSL_CTX_set_cipher_list(openssl_context, "aNULL") != 1)
        printf("SET CIPHER\n\n");
    
    //Create SSL
    openssl_SSL = SSL_new(openssl_context);
    if(openssl_SSL == NULL)
        printf("new ssl fail");
    SSL_set_fd(openssl_SSL, sockfd);

    //Connect SSL
    if(SSL_connect(openssl_SSL) < 0)
    {
        printf("SSL_Connect() failed");
    }
    else
    {
        printf("SSL_Connect() success");
    }


    //Authenticate
    int isAuthenticated = authenticateServer(openssl_SSL);
    printf("isAuthenticated: %u \n",isAuthenticated); 

    SSL_shutdown(openssl_SSL);
	
    return 0;
}
