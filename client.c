#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include <iostream>
#include "iotAuth.h"
#include "utils.h"

#define DEFAULT_PORT 8888

using namespace std;

iotAuth iotAuth;
Utils utils;

int byteArrayToHexString(uint8_t *byte_array, int byte_array_len,
                         char *hexstr, int hexstr_len)
{
    int off = 0;
    int i;

    for (i = 0; i < byte_array_len; i ++) {
        off += snprintf(hexstr + off, hexstr_len - off,
                           "%02x", byte_array[i]);
    }

    hexstr[off] = '\0';

    return off;
}

int main(int argc, char *argv[]){

    struct sockaddr_in servidor,cliente;
    int meuSocket;
    socklen_t tam_cliente;
    char envia[556];
    char recebe[556];
    struct hostent *server;

    if (argv[1] == NULL) {
        fprintf(stderr, "ERROR, no such host\n");
        exit(0);
    }
    server = gethostbyname(argv[1]);
    if (server == NULL) {
        fprintf(stderr, "ERROR, no such host\n");
        exit(0);
    }

    bcopy((char *)server->h_addr,
         (char *)&servidor.sin_addr.s_addr,
         server->h_length);

    meuSocket=socket(PF_INET,SOCK_DGRAM,0);
    servidor.sin_family=AF_INET; // familia de endereços
    servidor.sin_port=htons(DEFAULT_PORT); // porta
    // para usar um ip qualquer use inet_addr("10.10.10.10"); ao invés de htonl(INADDR_ANY)
    // servidor.sin_addr.s_addr=htonl(INADDR_ANY);
    // servidor.sin_addr.s_addr=inet_addr("150.162.237.172");

    memset(envia, 0, sizeof(envia));
    memset(recebe, 0, sizeof(recebe));

    while(1){
       printf("\n*** Bem vindo ao cliente ***\n");
       printf("Escreva uma mensagem:\n");
       fgets(envia,556,stdin);

       byte plain[556];
       utils.CharToByte((unsigned char*)envia, plain, sizeof(envia));
       char cipherHex[128];

       iotAuth.encrypt(plain, sizeof(plain), cipherHex, sizeof(cipherHex));
       cout << "Decifrado em HEXA (Client): " << cipherHex << endl;

       // byte plain2[64];
       // iotAuth.decrypt(plain2, sizeof(plain2), cipherHex, sizeof(cipherHex));
       // cout << "Decifrado em CHAR (Client): " << plain2 << endl;

       // iotAuth.decrypt(plain2, sizeof(plain2), cipher, sizeof(cipher));

       sendto(meuSocket,cipherHex,strlen(cipherHex),0,(struct sockaddr*)&servidor,sizeof(struct sockaddr_in));
       tam_cliente=sizeof(struct sockaddr_in);
       recvfrom(meuSocket,recebe,556,MSG_WAITALL,(struct sockaddr*)&cliente,&tam_cliente);
       printf("Recebi:%s",recebe);
       memset(envia, 0, sizeof(envia));
       memset(recebe, 0, sizeof(recebe));
    }
    close(meuSocket);
}
