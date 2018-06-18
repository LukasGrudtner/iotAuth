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

        char *decodifica(int *mensagemC, long long d, long long n, int quant);
        int *codifica(char *mensagem, long long e, long long n, int quant);
        long potencia(long long a, long long e, long long n);
        long long mdcEstendido(long long a, long long b);
        void divisao(long long *resto, long long *quociente, long long a, long long b);
        long long escolheE(long long phi, long long p, long long p2, long long n);
        long geraPrimo(long numero);
        long long verificaPrimo(long long p);
        long geraNumeroRandom();
        long geraNumeroMax(int n);
        int expModular(int a, int b, int n);
        char to_hex(long num);

    private:

};

#endif
