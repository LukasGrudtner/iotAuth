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

        template<typename T>
        void ObjectToBytes(T& object, byte byteArray[], int size)
        {
            memset(byteArray, 0, size);
            array<byte, sizeof(object)> array_bytes = to_bytes(object);
            copy(array_bytes.begin(), array_bytes.end(), byteArray);
        }

        template<typename T>
        void BytesToObject(byte byteArray[], T& object, int size)
        {
            array<byte, sizeof(T)> array_bytes;
            for (int i = 0; i < size; i++)
                array_bytes.at(i) = byteArray[i];

            object = from_bytes(array_bytes, object);
        }


        void CharToUint8_t(char charArray[], uint8_t byteArray[], int size);
        void HexStringToCharArray(string hexString, int sizeHexString, char charArray[]);
        string Uint8_tToHexString(uint8_t i[], int quant);
        int ByteArrayToHexString(uint8_t *byte_array, int byte_array_len, char *hexstr, int hexstr_len);
        void HexStringToByteArray(char *hexstr, int hexstr_len, uint8_t *byte_array, int byte_array_len);
        void CharToByte(unsigned char* chars, byte* bytes, unsigned int count);
        void ByteToChar(byte* bytes, char* chars, unsigned int count);

    private:
        std::vector<unsigned char> hex_to_bytes(std::string const& hex);

        /* Converte um objeto T em um array de bytes. */
        template<typename T>
        array< byte, sizeof(T)> to_bytes(const T& object)
        {
            std::array< byte, sizeof(T) > bytes ;

            const byte* begin = reinterpret_cast< const byte* >( std::addressof(object) ) ;
            const byte* end = begin + sizeof(T) ;
            std::copy( begin, end, std::begin(bytes) ) ;

            return bytes ;
        }

        /* Converte um array de bytes em um objeto T. */
        template<typename T>
        T& from_bytes(const array<byte, sizeof(T)> &bytes, T& object)
        {
            // http://en.cppreference.com/w/cpp/types/is_trivially_copyable
            static_assert( std::is_trivially_copyable<T>::value, "not a TriviallyCopyable type" ) ;

            byte* begin_object = reinterpret_cast< byte* >( std::addressof(object) ) ;
            std::copy( std::begin(bytes), std::end(bytes), begin_object ) ;

            return object ;
        }
};

#endif
