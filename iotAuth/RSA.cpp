#include "RSA.h"

char RSA::to_hex(long num){
	char a[] = "0123456789abcdef";
	char result;

	int c = 0;

	// get N somehow

	do
		result = a[num % 16];
	while((int) (num /= 16) > 0);

	return result;
	//result[c] = 0;
}

int RSA::expModular(int a, int b, int n){
    int z = 0;
    if(b==0){
        return 1;
    };
    z = expModular(a, floor(b/2), n) % n;
    if(b%2 == 0){
        return (z*z) % n;
    }else{
        return (z*z*a) % n ;
    }
}

long RSA::geraNumeroMax(int n){
    return rand() % n + 1;
}

long RSA::geraNumeroRandom(){
	/*char res;
	res = to_hex(10);
	printf("\n NUMERO:10 RES: %c \n", res);*/

    return rand() % 100;
}

//Descobre se um número é primo verificando se ele é divisível para qualquer i até a sua raiz quadrada
long long RSA::verificaPrimo(long long p){

	long long i;
	double j;

	//Calcula a raiz quadrada para p
	j = sqrt(p);


	for(i = 2; i <= j; i++){
		//Retorna 0 caso não seja um número primo
		if(p%i == 0)
			return 0;
	}

	//Retorna 1 quando é um número primo
	return 1;
}

// GERAR NOVO PRIMO
long RSA::geraPrimo(long numero){
    long primo;
    primo = geraNumeroRandom();
    while(verificaPrimo(primo) != 1){/*Em quanto primalidade não for igual a 1 que é verdadeiro*/
        primo = geraNumeroMax(numero); /*Gerando numero aleatorio entre 1 e X*/
    }
    return primo;
}

//Escolhe o menor primo que divide o coeficiente de euler. Obs: Ele deve ser diferente de p e p2.
long long RSA::escolheE(long long phi, long long p, long long p2, long long n){

	long long i, e;
	for(i = 2; i < phi; i++){

		if(phi%i != 0 && verificaPrimo(i) && i != p && i != p2){
			e = i;
			break;
		}
	}

	return e;
}

//Calcula o resto e o quociente de uma divisão
void RSA::divisao(long long *resto, long long *quociente, long long a, long long b){

	if(a >= 0){

		*quociente = 0;
		*resto = a;

		while(*resto >= b){

			*resto -= b;
			*quociente = *quociente + 1;
		}
	}
}

//Calcula o mdc estendido e retorna o beta(inverso do e módulo phi) para ser o d
long long RSA::mdcEstendido(long long a, long long b){

	long long resto, quociente, xB = 1, yB = 0, x = 0, y = 1, alpha, beta, phi;
	phi = a;

	resto = a;
	while(resto != 0){
		divisao(&resto, &quociente, a, b);
		a = b;
		b = resto;
		if(resto > 0){
			alpha = xB - quociente *x;
			beta = yB - quociente * y;

			xB = x;
			yB = y;
			x = alpha;
			y = beta;
		}
	}

	if(beta < 0)
		beta = phi + beta;

	return beta;
}

//Calcula a forma reduzida de a^e módulo n, usando a expansão binária do expoente
long RSA::potencia(long long a, long long e, long long n){

	long long A = a, P = 1, E = e;

	while(1){

		//Chegou ao fim da expansão, retorna o P
		if(E == 0)
			return P;

		//Se o expoente é ímpar
		else if(E%2 != 0){
			//Realizamos a redução módulo n de cada uma das multpilicações
			P = (A * P)%n;
			E = (E-1)/2;
		}

		//Se o expoente é par
		else{
			E = E/2;
		}
		//Obtém a sequência de potências
		A = (A*A)%n;
	}
}

//Codifica uma string de caracteres usando o resto da divisão de a^e por n para cada caractere, para a é utilizado o código da tabela ASCII
int *RSA::codifica(char *mensagem, long long e, long long n, int quant){

	long long i;
	int *mensagemC;
	long VALOR;
	mensagemC = (int*)malloc(quant * sizeof(long long));
	for(i = 0; i < quant; i++){
		VALOR = potencia(mensagem[i], e, n);
		// ESSE VALOR QUE TEM QUE CONVERTER PARA HEXADECIMAL
		mensagemC[i] = VALOR;
	}

	//Retorna um vetor de long longeiros
	return mensagemC;
}

//Decodifica um vetor de inteiros em uma string de caracteres usando o resto da divisão de a^d por n para cada inteiro
char *RSA::decodifica(int *mensagemC, long long d, long long n, int quant){

	long long i;
	char *mensagem;

	mensagem = (char*)malloc(quant * sizeof(char));

	for(i = 0; i < quant; i++){
		mensagem[i] = potencia(mensagemC[i], d, n);
	}

	return mensagem;
}
