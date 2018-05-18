#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <string.h>
#include <string>
#include <vector>
#include <iostream>
#include <sstream>
#include <array>
#include <memory>
#include <type_traits>
#include <iomanip>
#include "settings.h"

using namespace std;

class Utils
{
    protected:

    public:
        void charToUint8_t(char charArray[], uint8_t byteArray[], int size);
        void hexStringToCharArray(string hexString, int sizeHexString, char charArray[]);
        string Uint8_t_to_Hex_String(uint8_t i[], int quant);
        void RSAToIntArray(int intArray[], string encrypted, int size);
        int ByteArrayToHexString(uint8_t *byte_array, int byte_array_len, char *hexstr, int hexstr_len);
        void HexStringToByteArray(char *hexstr, int hexstr_len, uint8_t *byte_array, int byte_array_len);
        void CharToByte(unsigned char* chars, byte* bytes, unsigned int count);
        void ByteToChar(byte* bytes, char* chars, unsigned int count);
        int intArraySize(int array[]);
        int countMarks(string encrypted);

    private:
        std::vector<unsigned char> hex_to_bytes(std::string const& hex);
};

#endif
