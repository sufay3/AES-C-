#include "stdafx.h"
#include "AES.h"
#include "zbase64.h"
#include <malloc.h>

int Change(const char s[], char bits[]) {
	int i, n = 0;
	for (i = 0; s[i]; i += 2) {
		if (s[i] >= 'A' && s[i] <= 'F')
			bits[n] = s[i] - 'A' + 10;
		else bits[n] = s[i] - '0';
		if (s[i + 1] >= 'A' && s[i + 1] <= 'F')
			bits[n] = (bits[n] << 4) | (s[i + 1] - 'A' + 10);
		else bits[n] = (bits[n] << 4) | (s[i + 1] - '0');
		++n;
	}
	return n;
}

char* HexToByteArray(const char* hex, char* byte)
{
	Change(hex, byte);
	return byte;
}

char* WINAPI AESEncrypt(const char* source, const char* keyHex)
{
	ZBase64 base64;
	char cipherHex[1024];

	int keyLen = strlen(keyHex) / 2;
	char *key = (char*)malloc(keyLen);

	AES aes((unsigned char*)HexToByteArray(keyHex, key));
	aes.Bm53Cipher((char*)source, cipherHex);

	char *cipherByte = (char*)malloc(strlen(cipherHex) / 2);
	std::string cipher64 = base64.Encode((const unsigned char*)HexToByteArray(cipherHex, cipherByte), strlen(cipherHex) / 2);

	char *cipher = (char*)malloc(cipher64.length() + 1);
	memcpy(cipher, cipher64.c_str(), cipher64.length() + 1);

	free(key);
	free(cipherByte);

	return cipher;
}

char* WINAPI AESDecrypt(const char* cipherHex, const char* keyHex)
{
	char source[1024];

	int keyLen = strlen(keyHex) / 2;
	char *key = (char*)malloc(keyLen);

	AES aes((unsigned char*)HexToByteArray(keyHex, key));
	aes.Bm53InvCipher((char*)cipherHex, source);

	char *pSource = (char*)malloc(strlen(source) + 1);
	memcpy(pSource, source,strlen (source) + 1);

	free(key);
	return pSource;
}

void WINAPI AESFree(char* pointer) //free pointer
{
	if(pointer)
		free(pointer);
}
