#ifndef RSA_H
#define RSA_H

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>
#include <string.h>

class RSA
{
    public:

        char *decodifica(int *mensagemC, long d, long n, int quant);
        int *codifica(char *mensagem, long e, long n, int quant);
        long potencia(long a, long e, long n);
        long mdcEstendido(long a, long b);
        void divisao(long *resto, long *quociente, long a, long b);
        long escolheE(long phi, long p, long p2, long n);
        long geraPrimo(long numero);
        long verificaPrimo(long p);
        long geraNumeroRandom();
        long geraNumeroMax(int n);
        int expModular(int a, int b, int n);
        char to_hex(long num);

    private:

};

#endif
