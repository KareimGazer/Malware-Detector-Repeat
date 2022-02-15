#include <stdlib.h>
#include <unistd.h>

int main(){

  while(1){
    char * space = (char *) malloc(900 * 1024 * 1024);
    sleep(5);
    free(space);
    sleep(5);
  }
  return 0;
}
