#include <iostream>
#include <string>
#include <vector>
#include <openssl/rc4.h>
#include "cryptotest.h"

using namespace std;

string RC4_Encrypt(const string cleartext, const string key)
{
	RC4_KEY rc4key;
	unsigned char* tmp = new unsigned char[cleartext.length() + 1];
	memset(tmp, 0, cleartext.length() + 1);

	RC4_set_key(&rc4key, key.length(), (const unsigned char*)key.c_str());
	RC4(&rc4key, cleartext.length(), (const unsigned char*)cleartext.c_str(), tmp);

	string str = (char*)tmp;

	delete [] tmp;

	return str;
}

string RC4_Decrypt(const string ciphertext, const string key)
{
	RC4_KEY rc4key;
	unsigned char* tmp = new unsigned char[ciphertext.length() + 1];
	memset(tmp, 0, ciphertext.length() + 1);

	RC4_set_key(&rc4key, key.length(), (const unsigned char*)key.c_str());
	RC4(&rc4key, ciphertext.length(), (const unsigned char*)ciphertext.c_str(), tmp);

	string str = (char*)tmp;

	delete [] tmp;

	return str;
}