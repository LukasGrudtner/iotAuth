#include "iotAuth.h"

/*  encryptAES()
    Realiza a cifragem de plaintext com o algoritmo AES, onde o resultado é
    é retornado.
*/

uint8_t* IotAuth::encryptAES(uint8_t* plaintext, uint8_t* key, uint8_t* iv, int size)
{
    uint8_t *ciphertext = plaintext;

    struct AES_ctx ctx;
    aes.AES_init_ctx_iv(&ctx, key, iv);
    aes.AES_CBC_encrypt_buffer(&ctx, ciphertext, size);

    return ciphertext;
}

/*  decryptAES()
    Função interna.
    Realiza decrifragem de ciphertext com o algoritmo AES, onde o resultado é
    retornado.
*/
uint8_t* IotAuth::decryptAES(uint8_t ciphertext[], uint8_t key[], uint8_t iv[], int size)
{
    uint8_t *plaintext = ciphertext;

    struct AES_ctx ctx;
    aes.AES_init_ctx_iv(&ctx, key, iv);
    aes.AES_CBC_decrypt_buffer(&ctx, plaintext, size);

    return plaintext;
}

/*  Realiza a geração de um par de chaves RSA, retornando uma struct RSAKeyPair
    com ambas as chaves. Essa struct é definida em "settings.h". */
RSAKeyPair IotAuth::generateRSAKeyPair()
{
    sleep(1);
    srand(time(NULL));
    int p, p2, n, phi, e, d;

    p = rsa.geraPrimo(100*rsa.geraNumeroRandom());
    p2 = rsa.geraPrimo(100*rsa.geraNumeroRandom());

    //Calcula o n
	n = p * p2;

    //Calcula o quociente de euler
	phi = (p - 1)*(p2 - 1);

    //Escolhe o e para calcular a chave privada
	e = rsa.escolheE(phi, p, p2, n);

    //Escolhe o d para calcular a chave pública
	d = rsa.mdcEstendido(phi, e);

    RSAKey publicKey = {d, n};
    RSAKey privateKey = {e, n};
    RSAKeyPair keys = {publicKey, privateKey};

    return keys;
}

/*  Realiza o hash do parâmetro message */
string IotAuth::hash(string *message)
{
    return sha512(*message);
}

/* Realiza a cifragem RSA utilizando uma chave RSA fornecida por parâmetro. */
int* IotAuth::encryptRSA(string* plain, RSAKey* rsaKey, int size)
{
    char plainChar[plain->length()];
    strncpy(plainChar, plain->c_str(), sizeof(plainChar));

    int* mensagemC = new int[size];
    rsa.codifica(mensagemC, plainChar, rsaKey->d, rsaKey->n, sizeof(plainChar));

    return mensagemC;
}

int* IotAuth::encryptRSA(byte plain[], RSAKey* rsaKey, int size)
{
    int* mensagemC = new int[size];
    rsa.codifica(mensagemC, plain, rsaKey->d, rsaKey->n, size);

    return mensagemC;
}

/* Realiza a decifragem RSA utilizando uma chave RSA fornecida por parâmetro */
/* RSAKey é uma struct definida em "settings.h" */
byte* IotAuth::decryptRSA(int *cipher, RSAKey *rsaKey, int size)
{
    byte* plain = new byte[size];
    memset(plain, 0, sizeof(plain));
    rsa.decodifica(plain, cipher, rsaKey->d, rsaKey->n, size);

    return plain;
}

/*  Gera um número aleatório menor que um dado limite superior. */
int IotAuth::randomNumber(int upperBound)
{
    sleep(1);
    srand(time(NULL));
    return rand() % upperBound;
}

/*  Retorna um valor aleatório para ser usado como IV. */
int IotAuth::generateIV()
{
    sleep(1);
    return randomNumber(100);
}

/* Gera um FDR aleatório. */
FDR IotAuth::generateFDR()
{
    FDR fdr;
    fdr.setOperator('+');
    fdr.setOperand(randomNumber(100));

    return fdr;
}

/* Verifica se o HASH dado é idêntico ao HASH da mensagem. */
bool IotAuth::isHashValid(string *message, string *hash) {
    string hash2 = this->hash(message);
    return *hash == hash2;
}
