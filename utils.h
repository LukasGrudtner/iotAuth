#ifndef UTILS_H
#define UTILS_H

#include <string>
#include <vector>
#include <iostream>
#include <sstream>
#include "AES.h"

using namespace std;

class Utils
{
    protected:

    public:

        int ByteArrayToHexString(uint8_t *byte_array, int byte_array_len, char *hexstr, int hexstr_len);
        void HexStringToByteArray(char *hexstr, int hexstr_len, uint8_t *byte_array, int byte_array_len);
        void CharToByte(unsigned char* chars, byte* bytes, unsigned int count);
        void ByteToChar(byte* bytes, char* chars, unsigned int count);

    private:
        std::vector<unsigned char> hex_to_bytes(std::string const& hex);
};

#endif
