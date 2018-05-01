#ifndef SETTINGS_H
#define SETTINGS_H

#define DEFAULT_PORT 8888
#define SPACER '#'
#define SPACER_S "#"
#define HELLO_MESSAGE "HELLO\n"
#define DONE_MESSAGE "DONE\n"
#define HELLO_ACK "#"
#define DONE_ACK "!"

typedef struct dh_exchange
{
    unsigned long long int key_public;
    unsigned long long int iv;
    unsigned long long int answer_fdr;
    char operator_fdr;
    unsigned long long int operand_fdr;
} DHExchange;



#endif
