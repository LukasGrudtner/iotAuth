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
