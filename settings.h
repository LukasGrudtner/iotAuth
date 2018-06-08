#ifndef SETTINGS_H
#define SETTINGS_H

#include "fdr.h"

/* Definição de alguns atributos utilizados na comunicação */
#define VERBOSE true
#define VERBOSE_2 false
#define DEFAULT_PORT 8080
#define SPACER '#'
#define SPACER_S "#"
#define HELLO_MESSAGE "HELLO"
#define DONE_MESSAGE "DONE"
#define HELLO_ACK "#"
#define HELLO_ACK_CHAR '#'
#define DONE_ACK "!"
#define DONE_ACK_CHAR '!'

/* Definição do tipo "byte" utilizado. */
typedef unsigned char byte;

/* Definição da struct de chave RSA. */
typedef struct rsa_key
{
    int d, n;
} RSAKey;

/* Definição da struct que contém o par de chaves RSA. */
typedef struct rsa_key_pair
{
    RSAKey publicKey;
    RSAKey privateKey;
} RSAKeyPair;

// /* Definição da struct que represneta o pacote de dados trocados no passo RSA. */
// typedef struct rsaExchange
// {
//     PublicRSAKey publicKey;
//     unsigned long int answerFdr;
//     unsigned long int iv;
//     char operatorFdr;
//     unsigned long int operandFdr;
// } RSAExchange;
//
// typedef struct dhPackage
// {
//     byte *sessionKey;
//     long int g;
//     long int p;
//     long int iv;
//     long int Fiv;
// } DHPackage;
//
// typedef struct dhExchange
// {
//     char hash[128];
//     byte encryptedDHPackage[sizeof(DHPackage)];
// } DHExchange;


#endif
