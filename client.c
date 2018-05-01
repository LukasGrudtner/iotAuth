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

       /* PASSO 1: Envio de HELLO. */
       char a[] = "HELLO\n";
       sendto(meuSocket, a, sizeof(a),0,(struct sockaddr*)&servidor,sizeof(struct sockaddr_in));

       /* PASSO 3: Envio do pacote RSA (Chave pública, iv, FDR). */
       RSAKeyPair keys = iotAuth.generateRSAKeyPair();
       RSAExchange RSAExchangeStruct = {keys.publicRSAKey, 0, 111, '+', 100};
       sendto(meuSocket, (RSAExchange*)&RSAExchangeStruct, sizeof(RSAExchangeStruct),0,(struct sockaddr*)&servidor,sizeof(struct sockaddr_in));

       /* PASSO 5:
            (DH, g, p, iv, F(iv)) -> HASH,                              }   ->  Cifrado com a chave
            (DH, g, p, iv, F(iv)) -> Cifrado com chave privada de A     }   ->  pública de B
        */

        byte *sessionKey = (unsigned char*) "12345"; // supondo que o cliente calculou está chave
        long long int g = 10;
        long long int p = 20;
        long long int iv = 1111;
        long long int fiv = 1001;

        DHPackage dh = {sessionKey, g, p, iv, fiv};
        cout << "Struct Hash: " << iotAuth.hashDHPackage(dh) << endl;
        // char sessionKeyChar[sizeof(sessionKey)];
        // utils.ByteToChar(sessionKey, sessionKeyChar, sizeof(sessionKey));
        // string sessionKeyString (sessionKeyChar);
        // string struct_concat = sessionKeyString + to_string(g) + to_string(p) + to_string(iv) + to_string(fiv);
        // char hash[struct_concat.length()];
        // strncpy(hash, struct_concat.c_str(), sizeof(hash));

        // byte byteArray[sizeof(dh)];
        // utils.ObjectToBytes(dh, byteArray, sizeof(byteArray));
        //
        // char hex[sizeof(byteArray)*2];
        // utils.ByteArrayToHexString(byteArray, sizeof(byteArray), hex, sizeof(hex));
        // cout << "Struct de Bytes para Hex: " << hex << endl;
        //
        // char structChar[sizeof(byteArray)];
        // utils.ByteToChar(byteArray, structChar, sizeof(structChar));
        //
        // string hashString = iotAuth.hash(structChar);
        //
        // char hash[128];
        // strncpy(hash, hashString.c_str(), sizeof(hash));

        // cout << "Struct concat: " << struct_concat << endl;
        // cout << "Hash da Struct: " << iotAuth.hash(struct_concat) << endl;
        // cout << "Hash de HELLO: " << iotAuth.hash(a) << endl;
        //
        // DHPackage retorno = {};
        // utils.BytesToObject(byteArray, retorno, sizeof(byteArray));
        // cout << "Retorno -> g = " << retorno.g << ", p = " << retorno.p << ", iv = " << retorno.iv << ", Fiv = " << retorno.Fiv << endl;


       // RSAKeyPair keys = iotAuth.generateRSAKeyPair();
       // cout << "Chave Pública (" << keys.publicRSAKey.d << ", " << keys.publicRSAKey.n << ")." << endl;
       // cout << "Chave Privada (" << keys.privateRSAKey.e << ", " << keys.privateRSAKey.n << ")." << endl;
       //
       // DHExchange teste = {1010, 111, 1, '+', 5};
       //
       // // DHExchange test;
       // // test = from_bytes(array_bytes, test);
       // // cout << "Test.iv: " << test.iv << endl;
       //
       // /* Transforma a struct 'teste' em um array de bytes. */
       // array<byte, sizeof(teste)> array_bytes = utils.to_bytes(teste);
       // byte plain[array_bytes.size()];
       // copy(array_bytes.begin(), array_bytes.end(), plain);
       //
       // /* Realiza a cifragem de plain (contém a struct em bytes) */
       // char cipherHex[128];
       // iotAuth.encryptHEX(plain, sizeof(plain), cipherHex, sizeof(cipherHex));
       // cout << "Cipher Hex: " << cipherHex << endl;
       //
       // /* Realiza a decifragem de cipherHex, e coloca o resultado em plain2 */
       // byte plain2[sizeof(plain)];
       // iotAuth.decryptHEX(plain2, sizeof(plain2), cipherHex, sizeof(cipherHex));
       //
       // /* Converte plain2 para um array (classe array) de bytes */
       // array<byte, sizeof(plain2)> array_bytes2;
       // for (int i = 0; i < sizeof(plain2); i++) {
       //     array_bytes2.at(i) = plain2[i];
       // }
       //
       // /* Converte o array de bytes de volta na struct */
       // DHExchange test;
       // test = utils.from_bytes(array_bytes, test);
       // cout << "Test iv: " << test.iv << endl;


       // sendto(meuSocket,cipherHex,strlen(cipherHex),0,(struct sockaddr*)&servidor,sizeof(struct sockaddr_in));
       // sendto(meuSocket, (DHExchange*)&teste, sizeof(teste),0,(struct sockaddr*)&servidor,sizeof(struct sockaddr_in)); // Envio de struct
       // sendto(meuSocket,envia,strlen(envia),0,(struct sockaddr*)&servidor,sizeof(struct sockaddr_in));
       tam_cliente=sizeof(struct sockaddr_in);
       recvfrom(meuSocket,recebe,556,MSG_WAITALL,(struct sockaddr*)&cliente,&tam_cliente);
       printf("Recebi:%s",recebe);
       memset(envia, 0, sizeof(envia));
       memset(recebe, 0, sizeof(recebe));
    }
    close(meuSocket);
}
