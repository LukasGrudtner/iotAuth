#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <array>
#include <iostream>
#include "iotAuth.h"
#include "utils.h"
#include "settings.h"

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

template<typename T>
array< byte, sizeof(T)> to_bytes(const T& object)
{
    std::array< byte, sizeof(T) > bytes ;

    const byte* begin = reinterpret_cast< const byte* >( std::addressof(object) ) ;
    const byte* end = begin + sizeof(T) ;
    std::copy( begin, end, std::begin(bytes) ) ;

    return bytes ;
}

template<typename T>
T& from_bytes(const array<byte, sizeof(T)> &bytes, T& object)
{
    // http://en.cppreference.com/w/cpp/types/is_trivially_copyable
    static_assert( std::is_trivially_copyable<T>::value, "not a TriviallyCopyable type" ) ;

    byte* begin_object = reinterpret_cast< byte* >( std::addressof(object) ) ;
    std::copy( std::begin(bytes), std::end(bytes), begin_object ) ;

    return object ;
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

       // /* PASSO 1: Envio de HELLO. */
       // char a[] = "HELLO\n";
       // sendto(meuSocket, a, sizeof(a),0,(struct sockaddr*)&servidor,sizeof(struct sockaddr_in));

       // /* PASSO 3: Envio do pacote RSA (Chave pública, iv, FDR). */
       // RSAKeyPair keys = iotAuth.generateRSAKeyPair();
       // RSAExchange RSAExchangeStruct = {keys.publicRSAKey, 0, 111, '+', 100};
       // sendto(meuSocket, (RSAExchange*)&RSAExchangeStruct, sizeof(RSAExchangeStruct),0,(struct sockaddr*)&servidor,sizeof(struct sockaddr_in));

       /* PASSO 5:
            (DH, g, p, iv, F(iv)) -> HASH,                              }   ->  Cifrado com a chave
            (DH, g, p, iv, F(iv)) -> Cifrado com chave privada de A     }   ->  pública de B
        */


       // sendto(meuSocket,cipherHex,strlen(cipherHex),0,(struct sockaddr*)&servidor,sizeof(struct sockaddr_in));
       // sendto(meuSocket, (DHExchange*)&teste, sizeof(teste),0,(struct sockaddr*)&servidor,sizeof(struct sockaddr_in)); // Envio de struct
       sendto(meuSocket,envia,strlen(envia),0,(struct sockaddr*)&servidor,sizeof(struct sockaddr_in));
       tam_cliente=sizeof(struct sockaddr_in);
       recvfrom(meuSocket,recebe,1480,MSG_WAITALL,(struct sockaddr*)&cliente,&tam_cliente);

       string recebido (recebe);
       cout << "Recebi: " << recebido << endl;
       // printf("Recebi:%s",recebe);
       memset(envia, 0, sizeof(envia));
       memset(recebe, 0, sizeof(recebe));
    }
    close(meuSocket);
}
