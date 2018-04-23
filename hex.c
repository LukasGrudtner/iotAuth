char hexTab[16] = {'0', '1', '2', '3', '4', '5', '6', '7',
'8', '9', 'a', 'b', 'c', 'd', 'e', 'f', };

char hexToNibble(char n)
/* convert hexidecimal character to nibble. 0-9a-f. */
{
	return n - ( n <= '9' ? '0' : ('a'-10) );
}

void byteToHex(unsigned char n, char *hex)
/* convert byte to hexidecimal characters. 0 <= n <= 255. */
{
	*hex++ = hexTab[n >> 4];
	*hex++ = hexTab[n & 0xf];
}

unsigned char hexToByte(char *hex)
/* convert byte to hexidecimal characters. 0 <= n <= 255. */
{
	unsigned char n = hexToNibble(*hex++);
	n <<= 4;
	n += hexToNibble(*hex++);
	return n;
}
