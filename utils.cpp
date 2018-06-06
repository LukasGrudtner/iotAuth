#include "utils.h"

/*  Uint8_t_to_Hex_String
    Converte um arrau de uint8_t para string em hexadecimal.
*/
string Utils::Uint8_t_to_Hex_String(uint8_t i[], int quant){
  string saida = "";
  for(int j = 0; j < quant; j++){
    char buffer [3];
    // itoa (i[j],buffer,16);
    sprintf(buffer,"%02X",i[j]);
    saida += buffer;
  }
  return saida;
}

/*  ByteArrayToHexString()
    Converte um array de bytes em um array de chars em hexadecimal.
*/
int Utils::ByteArrayToHexString(uint8_t *byte_array, int byte_array_len, char *hexstr, int hexstr_len)
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

/*  HexStringToByteArray()
    Converte um array de chars em hexadecimal em um array de bytes.
*/
void Utils::HexStringToByteArray(char *hexstr, int hexstr_len, uint8_t *byte_array, int byte_array_len)
{
    string received_hexa (hexstr);
    vector<unsigned char> bytes_vector = hex_to_bytes(received_hexa);
    std::copy(bytes_vector.begin(), bytes_vector.end(), byte_array);
}

/*  hex_to_bytes()
    Função interna utilizada na conversão de um string de hexadecimais para
    um array de bytes.
*/
std::vector<unsigned char> Utils::hex_to_bytes(std::string const& hex)
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

/*  CharToByte()
    Realiza a conversão de chars para bytes.
*/
void Utils::CharToByte(unsigned char* chars, byte* bytes, unsigned int count)
{
    for(unsigned int i = 0; i < count; i++)
        bytes[i] = (byte)chars[i];
}

/*  ByteToChar()
    Realiza a conversão de bytes para chars.
*/
void Utils::ByteToChar(byte* bytes, char* chars, unsigned int count)
{
    for(unsigned int i = 0; i < count; i++)
         chars[i] = (char)bytes[i];
}

/*  O array recebido por parâmetro (encrypted) é composto por inteiros separados
    por um ponto (.), devido à cifragem RSA. Este método pega cada inteiro
    separado por ponto e retorna um array com estes números. */
void Utils::RSAToIntArray(int intArray[], string encrypted, int size)
{
    int k = 0;
    int i = 0;

    while (encrypted.at(i) != '!') {

        string numb = "";
        while ((encrypted.at(i) != '.') && (encrypted.at(i) != '!')) {
            numb += encrypted.at(i);
            i++;
        }

        if (encrypted.at(i) == '.')
            i++;

        intArray[k] = stoi(numb);
        k++;
    }
}

/* Retorna o tamanho de um array de ints. */
int Utils::intArraySize(int array[])
{
    int size = 0;
    int i = 0;

    while (array[i] != '\0') {
        size++;
        i++;
    }

    return size;
}

/* Conta o número de marcações (.) na string encriptada com RSA. */
int Utils::countMarks(string encrypted) {
    int marks = 0;
    for (int i = 0; i < encrypted.length(); i++) {
        if (encrypted.at(i) == '.')
            marks++;
    }

    return marks;
}

/* Converte uma string hexadecimal em um array de chars. */
void Utils::hexStringToCharArray(string hexString, int sizeHexString, char charArray[])
{
    char hexStringChar[sizeHexString];
    strncpy(hexStringChar, hexString.c_str(), sizeHexString);

    uint8_t byteArray[sizeHexString/2];

    HexStringToByteArray(hexStringChar, sizeHexString, byteArray, sizeHexString/2);
    ByteToChar(byteArray, charArray, sizeHexString/2);
}

/* Converte um array de char em um array de uint8_t. */
void Utils::charToUint8_t(char charArray[], uint8_t byteArray[], int size)
{
    for (int i = 0; i < size; i++) {
        byteArray[i] = uint8_t(charArray[i]);
    }
}
