#ifndef SETTINGS_H
#define SETTINGS_H

#define DEFAULT_PORT 8888
#define SPACER '#'
#define SEPARATOR "#"
#define SPACER_S "#"
#define HELLO_MESSAGE "HELLO"
#define DONE_MESSAGE "DONE"
#define HELLO_ACK "#"
#define HELLO_ACK_CHAR '#'
#define DONE_ACK "!"
#define DONE_ACK_CHAR '!'

#define FDRb "+7"

typedef unsigned char byte;

typedef struct private_rsa_key
{
    long e;
    long n;
} PrivateRSAKey;

typedef struct public_rsa_key
{
    long d;
    long n;
} PublicRSAKey;

typedef struct rsa_key_pair
{
    PublicRSAKey publicRSAKey;
    PrivateRSAKey privateRSAKey;
} RSAKeyPair;

typedef struct rsaExchange
{
    PublicRSAKey publicKey;
    unsigned long int answerFdr;
    unsigned long int iv;
    char operatorFdr;
    unsigned long int operandFdr;
} RSAExchange;

typedef struct dhPackage
{
    byte *sessionKey;
    long int g;
    long int p;
    long int iv;
    long int Fiv;
} DHPackage;

typedef struct dhExchange
{
    char hash[128];
    byte encryptedDHPackage[sizeof(DHPackage)];
} DHExchange;


#endif
