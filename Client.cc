#include <stdio.h>



/* Global variables used throughout the program
*/
char *serverAddress;
char *port;
char *action;



/*This function gets the arguments passed into the executable. It parses the
 * arguments to get the serverAddress, port, and send or receive action. 
*/
void getInput(int argc, char *argv[])
{


}


int main(int argc, char *argv[])
{
	for(int i = 0; i < argc; i++)
    {
        printf(argv[i]);
        printf("\n");

    }

    return 0;

}
