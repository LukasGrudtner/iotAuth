#include "iotAuth.h"



/*  encryptAES()
    Função interna.
    Realiza a cifragem de plain com o algoritmo AES, onde o resultado é
    armazenado no array cipher.
*/

uint8_t* IotAuth::encryptAES(uint8_t plaintext[], uint8_t key[], uint8_t iv[], int size)
{
    uint8_t *ciphertext = plaintext;

    struct AES_ctx ctx;
    aes.AES_init_ctx_iv(&ctx, key, iv);
    aes.AES_CBC_encrypt_buffer(&ctx, ciphertext, size);

    return ciphertext;
}

// void IotAuth::encryptAES(int bits, int cipher_size, byte *key, byte plain[], unsigned long long int my_iv, byte cipher[])
// {
//     aes.iv_inc();
//     byte iv[N_BLOCK];
//     memset(iv, 0, sizeof(iv));
//
//     aes.set_IV(my_iv);
//     aes.get_IV(iv);
//
//     aes.do_aes_encrypt(plain, cipher_size, cipher, key, bits, iv);
// }

/*  decryptAES()
    Função interna.
    Realiza decrifragem de cipher com o algoritmo AES, onde o resultado é
    armazenado no array plain.
*/
uint8_t* IotAuth::decryptAES(uint8_t ciphertext[], uint8_t key[], uint8_t iv[], int size)
{
    uint8_t *plaintext = ciphertext;

    struct AES_ctx ctx;
    aes.AES_init_ctx_iv(&ctx, key, iv);
    aes.AES_CBC_decrypt_buffer(&ctx, plaintext, size);

    return plaintext;
}

// void IotAuth::decryptAES(int bits, int cipher_size, byte *key, byte plain[], unsigned long long int my_iv, byte cipher[])
// {
//     byte iv[N_BLOCK];
//     memset(iv, 0, sizeof(iv));
//
//     aes.set_IV(my_iv);
//     aes.get_IV(iv);
//
//     int total = 16;
//     if(cipher_size > 16 && cipher_size <= 32){
//         total = 32;
//     }else if(cipher_size > 32 && cipher_size <= 48){
//         total = 48;
//     }else if(cipher_size > 48 && cipher_size <= 64){
//         total = 64;
//     }
//     aes.do_aes_decrypt(cipher, total, plain, key, bits, iv);
// }



/*  encrypt()
    Função utilizada na comunicação entre cliente e servidor, onde é realizada
    a cifragem do texto plano (plain, em bytes), e o resultado é armazenado
    em um array de char cipherHex, com o valor em hexadecimal.
*/


// void IotAuth::encryptHEX(byte plain[], int plain_size, char cipherHex[], int cipherHex_size)
// {
//     byte *key = (unsigned char*)"1234567891234567";
//     unsigned long long int iv = 11111111;
//     byte cipher[64];
//
//     memset(cipher, 0, sizeof(cipher));
//     memset(cipherHex, 0, cipherHex_size);
//
//     encryptAES(256, 64, key, plain, iv, cipher);
//     utils.ByteArrayToHexString(cipher, sizeof(cipher), cipherHex, cipherHex_size);
// }

/*  decrypt()
    Função utilizada na comunicação entre cliente e servidor, onde é realizada
    a decifragem do texto cifrado (cipher, em hexadecimal) e o resultado é
    armazenado em um array de bytes, plain.
*/
// void IotAuth::decryptHEX(byte plain[], int plain_size, char cipherHex[], int cipherHex_size)
// {
//     byte *key = (unsigned char*)"1234567891234567";
//     unsigned long long int iv = 11111111;
//
//     byte cipher[cipherHex_size/2];
//
//     memset(cipher, 0, sizeof(cipher));
//     memset(plain, 0, plain_size);
//
//     utils.HexStringToByteArray(cipherHex, cipherHex_size, cipher, sizeof(cipher));
//
//     decryptAES(256, 64, key, plain, iv, cipher);
// }

/*  Realiza a geração de um par de chaves RSA, retornando uma struct RSAKeyPair
    com ambas as chaves. Essa struct é definida em "settings.h". */
RSAKeyPair IotAuth::generateRSAKeyPair()
{
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

    PublicRSAKey publicRSAKey = {d, n};
    PrivateRSAKey privateRSAKey = {e, n};
    RSAKeyPair keys = {publicRSAKey, privateRSAKey};

    return keys;
}

/*  Realiza o hash do parâmetro message e armazena no array (hash) (retorno por
    parâmetro) */
string IotAuth::hash(char message[])
{
    return sha512(message);
}

/* Realiza a cifragem RSA utilizando uma chave pública fornecida por parâmetro */
string IotAuth::encryptRSAPublicKey(string plain, PublicRSAKey publicKey, int size)
{
    char plainChar[plain.length()];
    strncpy(plainChar, plain.c_str(), sizeof(plainChar));

    int mensagemC[size];
    rsa.codifica(mensagemC, plainChar, publicKey.d, publicKey.n, sizeof(plainChar));

    /* Converte o array de integer para uma string formatada. */
    string encrypted = "";
    for (int i = 0; i < size; i++) {
        encrypted += to_string(mensagemC[i]);
        if (i < (size-1))
            encrypted += ".";
    }

    return encrypted;
}

/* Realiza a cifragem RSA utilizando uma chave privada fornecida por parâmetro. */
string IotAuth::encryptRSAPrivateKey(string plain, PrivateRSAKey privateKey, int size)
{
    char plainChar[plain.length()];
    strncpy(plainChar, plain.c_str(), sizeof(plainChar));

    int mensagemC[size];
    rsa.codifica(mensagemC, plainChar, privateKey.e, privateKey.n, sizeof(plainChar));

    /* Converte o array de integer para uma string formatada. */
    string encrypted = "";
    for (int i = 0; i < size; i++) {
        encrypted += to_string(mensagemC[i]);
        if (i < (size-1))
            encrypted += ".";
    }

    return encrypted;
}

/* Realiza a decifragem RSA utilizando uma chave pública fornecida por parâmetro. */
/* PublicRSAKey é uma struct definida em "settings.h" */
string IotAuth::decryptRSAPublicKey(int cipher[], PublicRSAKey publicKey, int size)
{
    char plain[size];
    memset(plain, '\0', sizeof(plain));
    rsa.decodifica(plain, cipher, publicKey.d, publicKey.n, size);

    string output = "";
    for (int i = 0; i < sizeof(plain); i++) {
        output += plain[i];
    }

    return output;
}

/* Realiza a decifragem RSA utilizando uma chave privada fornecida por parâmetro */
/* PrivateRSAKey é uma struct definida em "settings.h" */
string IotAuth::decryptRSAPrivateKey(int cipher[], PrivateRSAKey privateKey, int size)
{
    char plain[size];
    rsa.decodifica(plain, cipher, privateKey.e, privateKey.n, size);

    string output (plain);
    return output;
}
