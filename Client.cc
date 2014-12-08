#include <stdio.h>
#include <stdlib.h>



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


int main(int argc, char *argv[])
{
    validateInput(argc,argv);
    getInput(argc,argv);
    return 0;

}
