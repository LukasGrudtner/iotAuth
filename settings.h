#ifndef SETTINGS_H
#define SETTINGS_H

#define DEFAULT_PORT 8888
#define SPACER '#'
#define SPACER_S "#"
#define HELLO_MESSAGE "HELLO\n"
#define DONE_MESSAGE "DONE\n"
#define HELLO_ACK "#"
#define DONE_ACK "!"

typedef unsigned char byte;

typedef struct private_rsa_key
{
    long long e;
    long long n;
} PrivateRSAKey;

typedef struct public_rsa_key
{
    long long d;
    long long n;
} PublicRSAKey;

typedef struct rsa_key_pair
{
    PublicRSAKey publicRSAKey;
    PrivateRSAKey privateRSAKey;
} RSAKeyPair;

typedef struct rsaExchange
{
    PublicRSAKey publicKey;
    unsigned long long int answerFdr;
    unsigned long long int iv;
    char operatorFdr;
    unsigned long long int operandFdr;
} RSAExchange;

typedef struct dhPackage
{
    byte *sessionKey;
    long long int g;
    long long int p;
    long long int iv;
    long long int Fiv;
} DHPackage;

typedef struct dhExchange
{
    char hash[128];
    byte encryptedDHPackage[sizeof(DHPackage)];
} DHExchange;


#endif
