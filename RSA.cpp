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

int RSA::geraNumeroRandom(){
	/*char res;
	res = to_hex(10);
	printf("\n NUMERO:10 RES: %c \n", res);*/

    return rand() % 100;
}

//Descobre se um número é primo verificando se ele é divisível para qualquer i até a sua raiz quadrada
long RSA::verificaPrimo(long p){

	long i;
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
int RSA::geraPrimo(int numero){
    int primo;
    primo = geraNumeroRandom();
    while(verificaPrimo(primo) != 1){/*Em quanto primalidade não for igual a 1 que é verdadeiro*/
        primo = geraNumeroMax(numero); /*Gerando numero aleatorio entre 1 e X*/
    }
    return primo;
}

//Escolhe o menor primo que divide o coeficiente de euler. Obs: Ele deve ser diferente de p e p2.
int RSA::escolheE(int phi, int p, int p2, int n){

	long i, e;
	for(i = 2; i < phi; i++){

		if(phi%i != 0 && verificaPrimo(i) && i != p && i != p2){
			e = i;
			break;
		}
	}

	return e;
}

//Calcula o resto e o quociente de uma divisão
void RSA::divisao(long *resto, long *quociente, long a, long b){

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
long RSA::mdcEstendido(long a, long b){

	long resto, quociente, xB = 1, yB = 0, x = 0, y = 1, alpha, beta, phi;
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
int RSA::potencia(long a, long e, long n){

	long A = a, P = 1, E = e;

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

// //Codifica uma string de caracteres usando o resto da divisão de a^e por n para cada caractere, para a é utilizado o código da tabela ASCII
// int *RSA::codifica(char *mensagem, long e, long n, int quant){
//
// 	long i;
// 	int *mensagemC;
// 	long VALOR;
// 	mensagemC = (int*)malloc(quant * sizeof(long));
// 	for(i = 0; i < quant; i++){
// 		VALOR = potencia(mensagem[i], e, n);
// 		// ESSE VALOR QUE TEM QUE CONVERTER PARA HEXADECIMAL
// 		mensagemC[i] = VALOR;
// 	}
//
// 	//Retorna um vetor de long longeiros
// 	return mensagemC;
// }

//Codifica uma string de caracteres usando o resto da divisão de a^e por n para cada caractere, para a é utilizado o código da tabela ASCII
void RSA::codifica(int encrypted[], char *mensagem, int e, int n, int quant){

	int i;
	int VALOR;
	for(i = 0; i < quant; i++){
		VALOR = potencia(mensagem[i], e, n);
		// ESSE VALOR QUE TEM QUE CONVERTER PARA HEXADECIMAL
		encrypted[i] = VALOR;
	}
}

//Codifica uma string de caracteres usando o resto da divisão de a^e por n para cada caractere, para a é utilizado o código da tabela ASCII
void RSA::codifica(int encrypted[], byte *mensagem, int e, int n, int quant){

	int i;
	int VALOR;
	for(i = 0; i < quant; i++){
		VALOR = potencia((int)mensagem[i], e, n);
		// ESSE VALOR QUE TEM QUE CONVERTER PARA HEXADECIMAL
		encrypted[i] = VALOR;
	}
}

//Decodifica um vetor de inteiros em uma string de caracteres usando o resto da divisão de a^d por n para cada inteiro
void RSA::decodifica(char message[], int mensagemC[], int d, int n, int quant){

	int i;

	for(i = 0; i < quant; i++){
		message[i] = potencia(mensagemC[i], d, n);
	}
}
