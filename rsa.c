#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>
#include <string.h>

char to_hex(long num){
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


int expModular(int a, int b, int n){
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

long geraNumeroMax(int n){
    return rand() % n + 1;
}

long geraNumeroRandom(){
	/*char res;
	res = to_hex(10);
	printf("\n NUMERO:10 RES: %c \n", res);*/

    return rand() % 100;
}


//Descobre se um número é primo verificando se ele é divisível para qualquer i até a sua raiz quadrada
long long verificaPrimo(long long p){

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
long geraPrimo(long numero){
    long primo;
    primo = geraNumeroRandom(numero);
    while(verificaPrimo(primo) != 1){/*Em quanto primalidade não for igual a 1 que é verdadeiro*/
        primo = geraNumeroMax(numero); /*Gerando numero aleatorio entre 1 e X*/
    }
    return primo;
}

//Escolhe o menor primo que divide o coeficiente de euler. Obs: Ele deve ser diferente de p e p2.
long long escolheE(long long phi, long long p, long long p2, long long n){

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
void divisao(long long *resto, long long *quociente, long long a, long long b){

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
long long mdcEstendido(long long a, long long b){

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
long potencia(long long a, long long e, long long n){

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
int *codifica(char *mensagem, long long e, long long n, int quant){

	long long i;
	int *mensagemC;
	long VALOR;
	mensagemC = malloc(quant * sizeof(long long));
	for(i = 0; i < quant; i++){
		VALOR = potencia(mensagem[i], e, n);
		// ESSE VALOR QUE TEM QUE CONVERTER PARA HEXADECIMAL
		mensagemC[i] = VALOR;
	}

	//Retorna um vetor de long longeiros
	return mensagemC;
}

//Codifica uma string de caracteres usando o resto da divisão de a^e por n para cada caractere, para a é utilizado o código da tabela ASCII
int *codifica(byte *mensagem, long long e, long long n, int quant){

	long long i;
	int *mensagemC;
	long VALOR;
	mensagemC = malloc(quant * sizeof(long long));
	for(i = 0; i < quant; i++){
		VALOR = potencia((int)mensagem[i], e, n);
		// ESSE VALOR QUE TEM QUE CONVERTER PARA HEXADECIMAL
		mensagemC[i] = VALOR;
	}

	//Retorna um vetor de long longeiros
	return mensagemC;
}

//Decodifica um vetor de inteiros em uma string de caracteres usando o resto da divisão de a^d por n para cada inteiro
char *decodifica(int *mensagemC, long long d, long long n, int quant){

	long long i;
	char *mensagem;

	mensagem = malloc(quant * sizeof(char));

	for(i = 0; i < quant; i++){
		mensagem[i] = potencia(mensagemC[i], d, n);
	}

	return mensagem;
}

//Programa principal
int main(void){

	srand(time(NULL)); // FORÇANDO A CRIRAR NOVOS VALORES
	long long i;
	long long p, p2, n, phi, e, d;

	// ATENÇÃO //
	int quant = 100;//A mensagem a ser criptografada pode ter no máximo 100 caracteres
	char mensagem[quant];
	char saida[quant];
	int *mensagemC;

	//Verifica se é um primo
	long long primoFlag;

	p = geraPrimo(100*geraNumeroRandom());
	printf("\nO primeiro número primo: %lld\n", p);

	//Faz a mesma coisa para o segundo primo
	p2 = geraPrimo(100*geraNumeroRandom());
	printf("\nO Segundo número primo: %lld\n", p2);

	//Lê a mensagem a ser criptografada
	printf("\nDigite uma mensagem\n");

	//Limpa o buuffer
	scanf("\n");
	fgets(mensagem, quant, stdin);

	//Calcula o n
	n = p * p2;

	//Calcula o quociente de euler
	phi = (p - 1)*(p2 - 1);

	//Escolhe o e para calcular a chave privada
	e = escolheE(phi, p, p2, n);

	printf("\nChave privada: (%llu, %llu)\n", e, n);

	//Escolhe o d para calcular a chave pública
	d = mdcEstendido(phi, e);

	printf("\nChave publica: (%llu, %llu)\n", d, n);

	//Codifica a mensagem
	mensagemC = codifica(mensagem, e, n, quant);

	//Imprime a mensagem codificada
	printf("\nMensagem encriptada: ");

	for(i = 0; i < strlen(mensagem); i++){
		printf("%c", mensagemC[i]);
	}
	printf("\n");

	//Decodifica a mensagem
	char *mensagemD;
	mensagemD = decodifica(mensagemC, d, n, quant);

	printf("\nMensagem desencriptada: %s\n\n", mensagemD);

	//Libera memória alocada
	free(mensagemC);
	free(mensagemD);
	return 0;

}
