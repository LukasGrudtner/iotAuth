#include "utils.h"

/*  Char to Uint_8t
    Converte um array de chars para um array de uint8_t.
*/
void CharToUint8_t(char* charArray, uint8_t* byteArray, int size)
{
    for (int i = 0; i < size; i++) {
        byteArray[i] = uint8_t(charArray[i]);
    }
}

/*  Uint8_t to Hex String
    Converte um array de uint8_t em uma string codificada em hexadecimal.
*/
string Uint8_tToHexString(uint8_t* i, int quant){
  string saida = "";

  for(int j = 0; j < quant; j++){
    char buffer [3];
    sprintf(buffer,"%02X",i[j]);
    saida += buffer;
  }

  return saida;
}

/*  Hex String to Char Array
    Converte uma string codificada em hexadecimal para um array de chars.
*/
void HexStringToCharArray(string* hexString, int sizeHexString, char* charArray)
{
    char hexStringChar[sizeHexString];
    strncpy(hexStringChar, hexString->c_str(), sizeHexString);

    uint8_t byteArray[sizeHexString/2];

    HexStringToByteArray(hexStringChar, sizeHexString, byteArray, sizeHexString/2);
    ByteToChar(byteArray, charArray, sizeHexString/2);
}

/*  Byte Array to Hex String
    Converte um array de bytes em uma string codificada em hexadecimal.
*/
int ByteArrayToHexString(uint8_t *byte_array, int byte_array_len, char *hexstr, int hexstr_len)
{
    int off = 0;
    int i;

    for (i = 0; i < byte_array_len; i ++) {
        off += snprintf(hexstr + off, hexstr_len - off,
                           "%02x", byte_array[i]);
    }

    hexstr[off] = '\0';

    return off;
}

/*  Hex String to Byte Array
    Converte uma string codificada em hexadecimal para um array de bytes.
*/
void HexStringToByteArray(char *hexstr, int hexstr_len, uint8_t *byte_array, int byte_array_len)
{
    string received_hexa (hexstr);
    vector<unsigned char> bytes_vector = hex_to_bytes(received_hexa);
    std::copy(bytes_vector.begin(), bytes_vector.end(), byte_array);
}

/*  Char to Byte
    Converte um array de chars para um array de bytes.
*/
void CharToByte(unsigned char* chars, byte* bytes, unsigned int count)
{
    for(unsigned int i = 0; i < count; i++)
        bytes[i] = (byte)chars[i];
}

/*  Byte to Char
    Converte um array de bytes para um array de char.
*/
void ByteToChar(byte* bytes, char* chars, unsigned int count)
{
    for(unsigned int i = 0; i < count; i++)
         chars[i] = (char)bytes[i];
}

/*  Função auxiliar utilizada na função 'Hex String to Byte Array'.
    Recebe uma string codificada em hexadecimal e retorna um vetor de chars.
*/
std::vector<unsigned char> hex_to_bytes(std::string const& hex)
{
    std::vector<unsigned char> bytes;
    bytes.reserve(hex.size() / 2);
    for (std::string::size_type i = 0, i_end = hex.size(); i < i_end; i += 2)
    {
        unsigned byte;
        std::istringstream hex_byte(hex.substr(i, 2));
        hex_byte >> std::hex >> byte;
        bytes.push_back(static_cast<unsigned char>(byte));
    }
    return bytes;
}
