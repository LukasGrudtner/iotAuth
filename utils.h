#ifndef UTILS_H
#define UTILS_H

#include <string>
#include <vector>
#include <iostream>
#include <sstream>
#include <array>
#include <memory>
#include <type_traits>
#include <iomanip>
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
        template< typename T > array< byte, sizeof(T) >  to_bytes( const T& object );
        template< typename T > T& from_bytes( const array< byte, sizeof(T) >& bytes, T& object );

    private:
        std::vector<unsigned char> hex_to_bytes(std::string const& hex);
};

#endif
