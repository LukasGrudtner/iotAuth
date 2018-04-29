#include "iotAuth.h"

void iotAuth::encryptAES(int bits, int cipher_size, byte *key, byte plain[], unsigned long long int my_iv, byte cipher[])
{
    aes.iv_inc();
    byte iv[N_BLOCK];

    aes.set_IV(my_iv);
    aes.get_IV(iv);

    aes.do_aes_encrypt(plain, cipher_size, cipher, key, bits, iv);
}

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

void iotAuth::encrypt(byte plain[], int plain_size, char cipherHex[], int cipherHex_size)
{
    byte *key = (unsigned char*)"1234567891234567";
    unsigned long long int iv = 11111111;
    byte cipher[64];

    memset(cipher, 0, sizeof(cipher));
    memset(cipherHex, 0, cipherHex_size);

    encryptAES(256, 64, key, plain, iv, cipher);
    utils.ByteArrayToHexString(cipher, sizeof(cipher), cipherHex, cipherHex_size);
    cout << "Cifrado em HEXA (iotAuth): " << cipherHex << endl;

    /* Testando método HexStringToByteArray */
    // byte cipher2[64];
    // utils.HexStringToByteArray(cipherHex, cipherHex_size, cipher2, sizeof(cipher2));
    // byte plain2[64];
    // decryptAES(256, 64, key, plain2, iv, cipher2);
    // cout << "Decifrado em CHAR (iotAuth): " << plain2 << endl;
}

void iotAuth::decrypt(byte plain[], int plain_size, char cipherHex[], int cipherHex_size)
{
    byte *key = (unsigned char*)"1234567891234567";
    unsigned long long int iv = 11111111;

    byte cipher[64];

    memset(cipher, 0, sizeof(cipher));
    memset(plain, 0, plain_size);

    utils.HexStringToByteArray(cipherHex, cipherHex_size, cipher, sizeof(cipher));

    decryptAES(256, 64, key, plain, iv, cipher);
    cout << "Decifrado em CHAR (iotAuth): " << plain << endl;
}
