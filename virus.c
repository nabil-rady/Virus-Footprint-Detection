#include "stdio.h"
#include "unistd.h"

int main(){
    for(;;){
        usleep(10000);
        printf("lol\n");
    }
    return 0;
}
