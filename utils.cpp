#include "utils.h"

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

void Utils::HexStringToByteArray(char *hexstr, int hexstr_len, uint8_t *byte_array, int byte_array_len)
{
    string received_hexa (hexstr);
    vector<unsigned char> bytes_vector = hex_to_bytes(received_hexa);
    std::copy(bytes_vector.begin(), bytes_vector.end(), byte_array);
}

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

void Utils::CharToByte(unsigned char* chars, byte* bytes, unsigned int count)
{
    for(unsigned int i = 0; i < count; i++)
        bytes[i] = (byte)chars[i];
}

void Utils::ByteToChar(byte* bytes, char* chars, unsigned int count)
{
    for(unsigned int i = 0; i < count; i++)
         chars[i] = (char)bytes[i];
}
