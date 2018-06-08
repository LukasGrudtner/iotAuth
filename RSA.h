#ifndef RSA_H
#define RSA_H

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>
#include <string.h>
#include <iostream>
#include "settings.h"

class RSA
{
    public:

        void decodifica(byte message[], int mensagemC[], int d, int n, int quant);
        // int *codifica(char *mensagem, long e, long n, int quant);
        void codifica(int encrypted[], char *mensagem, int e, int n, int quant);
        void codifica(int encrypted[], byte *mensagem, int e, int n, int quant);
        int potencia(long a, long e, long n);
        long mdcEstendido(long a, long b);
        void divisao(long *resto, long *quociente, long a, long b);
        int escolheE(int phi, int p, int p2, int n);
        int geraPrimo(int numero);
        long verificaPrimo(long p);
        int geraNumeroRandom();
        long geraNumeroMax(int n);
        int expModular(int a, int b, int n);
        char to_hex(long num);

    private:

};

#endif
