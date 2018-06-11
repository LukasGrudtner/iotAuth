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

/* Definição de todos os possíveis estados da FSM:
    HELLO   :   Aguardando pedido de início de conexão.
    DONE    :   Envia pedido de término de conexão.
    RFT     :   Envia confirmação de término de conexão.        :   Request for Termination
    WDC     :   Aguardando confirmação para término de conexão. :   Waiting Done Confirmation
    RRSA    :   Estado de recepção de chaves RSA;
    SRSA    :   Estado de envio de chaves RSA.
    RDH     :   Estado de recepção de chaves Diffie-Hellman.
    SDH     :   Estado de envio de chaves Diffie-Hellman.
    DT      :   Estado de transferência de dados cifrados.
*/
typedef enum {
    HELLO, DONE, RFT, WDC, RRSA, SRSA, RDH, SDH, DT
} States;

#endif
