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

/*  Object to Bytes
    Converte um objeto qualquer para um array de bytes.
*/
template<typename T>
void ObjectToBytes(T& object, byte byteArray[], int size)
{
    memset(byteArray, 0, size);
    array<byte, sizeof(object)> array_bytes = to_bytes(object);
    copy(array_bytes.begin(), array_bytes.end(), byteArray);
}

/*  Bytes to Object
    Converte um array de bytes em sua representação como objeto.
*/
template<typename T>
void BytesToObject(byte byteArray[], T& object, int size)
{
    array<byte, sizeof(T)> array_bytes;
    for (int i = 0; i < size; i++)
        array_bytes.at(i) = byteArray[i];

    object = from_bytes(array_bytes, object);
}

/*  Char to Uint_8t
    Converte um array de chars para um array de uint8_t.
*/
void CharToUint8_t(char* charArray, uint8_t* byteArray, int size);

/*  Uint8_t to Hex String
Converte um array de uint8_t em uma string codificada em hexadecimal.
*/
string Uint8_tToHexString(uint8_t* i, int quant);

/*  Hex String to Char Array
    Converte uma string codificada em hexadecimal para um array de chars.
*/
void HexStringToCharArray(string* hexString, int sizeHexString, char* charArray);

/*  Byte Array to Hex String
    Converte um array de bytes em uma string codificada em hexadecimal.
*/
int ByteArrayToHexString(uint8_t *byte_array, int byte_array_len, char *hexstr, int hexstr_len);

/*  Hex String to Byte Array
    Converte uma string codificada em hexadecimal para um array de bytes.
*/
void HexStringToByteArray(char *hexstr, int hexstr_len, uint8_t *byte_array, int byte_array_len);

/*  Char to Byte
    Converte um array de chars para um array de bytes.
*/
void CharToByte(unsigned char* chars, byte* bytes, unsigned int count);

/*  Byte to Char
    Converte um array de bytes para um array de char.
*/
void ByteToChar(byte* bytes, char* chars, unsigned int count);

/*  Função auxiliar utilizada na função 'Hex String to Byte Array'.
    Recebe uma string codificada em hexadecimal e retorna um vetor de chars.
*/
std::vector<unsigned char> hex_to_bytes(std::string const& hex);

/*  Função auxiliar utilizada pela função 'Object to Bytes'.
    Converte um objeto T em um array de bytes.
*/
template<typename T>
array< byte, sizeof(T)> to_bytes(const T& object)
{
    std::array< byte, sizeof(T) > bytes ;

    const byte* begin = reinterpret_cast< const byte* >( std::addressof(object) ) ;
    const byte* end = begin + sizeof(T) ;
    std::copy( begin, end, std::begin(bytes) ) ;

    return bytes ;
}

/*  Função auxiliar utilizada pela função 'Bytes to Object'.
    Converte um array de bytes em um objeto T.
*/
template<typename T>
T& from_bytes(const array<byte, sizeof(T)> &bytes, T& object)
{
    // http://en.cppreference.com/w/cpp/types/is_trivially_copyable
    static_assert( std::is_trivially_copyable<T>::value, "not a TriviallyCopyable type" ) ;

    byte* begin_object = reinterpret_cast< byte* >( std::addressof(object) ) ;
    std::copy( std::begin(bytes), std::end(bytes), begin_object ) ;

    return object ;
}

#endif
