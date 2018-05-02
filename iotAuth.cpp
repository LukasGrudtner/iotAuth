#include "iotAuth.h"

/*  encryptAES()
    Função interna.
    Realiza a cifragem de plain com o algoritmo AES, onde o resultado é
    armazenado no array cipher.
*/
void iotAuth::encryptAES(int bits, int cipher_size, byte *key, byte plain[], unsigned long long int my_iv, byte cipher[])
{
    aes.iv_inc();
    byte iv[N_BLOCK];

    aes.set_IV(my_iv);
    aes.get_IV(iv);

    aes.do_aes_encrypt(plain, cipher_size, cipher, key, bits, iv);
}

/*  decryptAES()
    Função interna.
    Realiza decrifragem de cipher com o algoritmo AES, onde o resultado é
    armazenado no array plain.
*/
void iotAuth::decryptAES(int bits, int cipher_size, byte *key, byte plain[], unsigned long long int my_iv, byte cipher[])
{
    byte iv[N_BLOCK];

    aes.set_IV(my_iv);
    aes.get_IV(iv);

    int total = 16;
    if(cipher_size > 16 && cipher_size <= 32){
        total = 32;
    }else if(cipher_size > 32 && cipher_size <= 48){
        total = 48;
    }else if(cipher_size > 48 && cipher_size <= 64){
        total = 64;
    }
    aes.do_aes_decrypt(cipher, total, plain, key, bits, iv);
}



/*  encrypt()
    Função utilizada na comunicação entre cliente e servidor, onde é realizada
    a cifragem do texto plano (plain, em bytes), e o resultado é armazenado
    em um array de char cipherHex, com o valor em hexadecimal.
*/
void iotAuth::encryptHEX(byte plain[], int plain_size, char cipherHex[], int cipherHex_size)
{
    byte *key = (unsigned char*)"1234567891234567";
    unsigned long long int iv = 11111111;
    byte cipher[64];

    memset(cipher, 0, sizeof(cipher));
    memset(cipherHex, 0, cipherHex_size);

    encryptAES(256, 64, key, plain, iv, cipher);
    utils.ByteArrayToHexString(cipher, sizeof(cipher), cipherHex, cipherHex_size);
    cout << "Cifrado em HEXA (iotAuth): " << cipherHex << endl;
}

void iotAuth::encryptDHPackage(DHPackage DHPackageStruct, int package_size, char cipherHex[], int cipherHex_size)
{
    byte *key = (unsigned char*)"1234567891234567";
    unsigned long long int iv = 11111111;
    byte cipher[64];

    memset(cipher, 0, sizeof(cipher));
    memset(cipherHex, 0, cipherHex_size);

    byte byteArray[sizeof(DHPackageStruct)];
    utils.ObjectToBytes(DHPackageStruct, byteArray, sizeof(byteArray));

    encryptAES(256, 64, key, byteArray, iv, cipher);
    utils.ByteArrayToHexString(cipher, sizeof(cipher), cipherHex, cipherHex_size);
    cout << "Cifrado em HEXA (iotAuth): " << cipherHex << endl;
}

void iotAuth::decryptDHPackage(DHPackage DHPackageStruct, int package_size, char cipherHex[], int cipherHex_size)
{
    byte *key = (unsigned char*)"1234567891234567";
    unsigned long long int iv = 11111111;

    byte plain[cipherHex_size/2];
    byte cipher[64];

    memset(cipher, 0, sizeof(cipher));
    memset(plain, 0, sizeof(plain));

    utils.HexStringToByteArray(cipherHex, cipherHex_size, cipher, sizeof(cipher));

    decryptAES(256, 64, key, plain, iv, cipher);

    utils.BytesToObject(plain, DHPackageStruct, sizeof(plain));
    cout << "DH Decifrado: g = " << DHPackageStruct.g << ", p = " << DHPackageStruct.p << ", iv = " << DHPackageStruct.iv << ", Fiv = " << DHPackageStruct.Fiv << endl;
}

/*  decrypt()
    Função utilizada na comunicação entre cliente e servidor, onde é realizada
    a decifragem do texto cifrado (cipher, em hexadecimal) e o resultado é
    armazenado em um array de bytes, plain.
*/
void iotAuth::decryptHEX(byte plain[], int plain_size, char cipherHex[], int cipherHex_size)
{
    byte *key = (unsigned char*)"1234567891234567";
    unsigned long long int iv = 11111111;

    byte cipher[cipherHex_size/2];

    memset(cipher, 0, sizeof(cipher));
    memset(plain, 0, plain_size);

    utils.HexStringToByteArray(cipherHex, cipherHex_size, cipher, sizeof(cipher));

    decryptAES(256, 64, key, plain, iv, cipher);
    cout << "Decifrado em CHAR (iotAuth): " << plain << endl;
}

RSAKeyPair iotAuth::generateRSAKeyPair()
{
    srand(time(NULL));
    long p, p2, n, phi, e, d;

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

string iotAuth::hashDHPackage(DHPackage DHPackageStruct)
{
    char sessionKeyChar[sizeof(DHPackageStruct.sessionKey)];
    utils.ByteToChar(DHPackageStruct.sessionKey, sessionKeyChar, sizeof(sessionKeyChar));
    string sessionKeyString (sessionKeyChar);
    string struct_concat =  sessionKeyString + to_string(DHPackageStruct.g) +
                to_string(DHPackageStruct.p) + to_string(DHPackageStruct.iv) +
                to_string(DHPackageStruct.Fiv);

    return hash(struct_concat);
}

string iotAuth::hash(string message)
{
    string output = sha512(message);

    return output;
}

int* iotAuth::encryptRSAPublicKey(char plain[], PublicRSAKey publicKey, int size)
{
    int* mensagemC;
    mensagemC = rsa.codifica(plain, publicKey.d, publicKey.n, size);

    string encrypted = "";
    for (int i = 0; i < size; i++)
        encrypted += to_string(mensagemC[i]);

    return mensagemC;
}

int* iotAuth::encryptRSAPrivateKey(char plain[], PrivateRSAKey privateKey, int size)
{
    int* mensagemC;
    mensagemC = rsa.codifica(plain, privateKey.e, privateKey.n, size);

    string encrypted = "";
    for (int i = 0; i < size; i++)
        encrypted += to_string(mensagemC[i]);

    return mensagemC;
}

string iotAuth::decryptRSAPublicKey(int cipher[], PublicRSAKey publicKey, int size)
{
    char* plain;
    plain = rsa.decodifica(cipher, publicKey.d, publicKey.n, size);

    string output (plain);
    return output;
}

string iotAuth::decryptRSAPrivateKey(int cipher[], PrivateRSAKey privateKey, int size)
{
    char* plain;
    plain = rsa.decodifica(cipher, privateKey.e, privateKey.n, size);

    string output (plain);
    return output;
}
