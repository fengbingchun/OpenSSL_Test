#include <iostream>
#include <string>
#include <vector>
#include <openssl/des.h>
#include "cryptotest.h"

using namespace std;

static unsigned char cbc_iv[8] = {'0', '1', 'A', 'B', 'a', 'b', '9', '8'};

string DES_Encrypt(const string cleartext, const string key, CRYPTO_MODE mode)
{
	string strCipherText;

	switch (mode) {
	case GENERAL:
	case ECB:
		{
			DES_cblock keyEncrypt;
			memset(keyEncrypt, 0, 8);

			if (key.length() <= 8) 
				memcpy(keyEncrypt, key.c_str(), key.length());
			else 
				memcpy(keyEncrypt, key.c_str(), 8);

			DES_key_schedule keySchedule;
			DES_set_key_unchecked(&keyEncrypt, &keySchedule);	

			const_DES_cblock inputText;
			DES_cblock outputText;
			vector<unsigned char> vecCiphertext;
			unsigned char tmp[8];

			for (int i = 0; i < cleartext.length() / 8; i ++) {
				memcpy(inputText, cleartext.c_str() + i * 8, 8);
				DES_ecb_encrypt(&inputText, &outputText, &keySchedule, DES_ENCRYPT);
				memcpy(tmp, outputText, 8);

				for (int j = 0; j < 8; j++)
					vecCiphertext.push_back(tmp[j]);
			}

			if (cleartext.length() % 8 != 0) {
				int tmp1 = cleartext.length() / 8 * 8;
				int tmp2 = cleartext.length() - tmp1;
				memset(inputText, 0, 8);
				memcpy(inputText, cleartext.c_str() + tmp1, tmp2);

				DES_ecb_encrypt(&inputText, &outputText, &keySchedule, DES_ENCRYPT);
				memcpy(tmp, outputText, 8);

				for (int j = 0; j < 8; j++)
					vecCiphertext.push_back(tmp[j]);
			}

			strCipherText.clear();
			strCipherText.assign(vecCiphertext.begin(), vecCiphertext.end());
		}
		break;
	case CBC:
		{
			DES_cblock keyEncrypt, ivec;
			memset(keyEncrypt, 0, 8);

			if (key.length() <= 8) 
				memcpy(keyEncrypt, key.c_str(), key.length());
			else 
				memcpy(keyEncrypt, key.c_str(), 8);

			DES_key_schedule keySchedule;
			DES_set_key_unchecked(&keyEncrypt, &keySchedule);	

			memcpy(ivec, cbc_iv, sizeof(cbc_iv));

			int iLength = cleartext.length() % 8 ? (cleartext.length() / 8 + 1) * 8 : cleartext.length();
			unsigned char* tmp = new unsigned char[iLength + 16];
			memset(tmp, 0, iLength);

			DES_ncbc_encrypt((const unsigned char*)cleartext.c_str(), tmp, cleartext.length()+1, &keySchedule, &ivec, DES_ENCRYPT);
	
			//strClearText = (char*)tmp; 这种写法有问题，从unsigned char*强转为char*，如果遇到内存中间存在0x0，
			//strClearText实际是截断的，应该做个base64加密运算再返回，解密时数据才是完整的
			//strCipherText = (char*)tmp;
			strCipherText = reinterpret_cast<char*>(tmp);

			delete [] tmp;
		}
		break;
	case CFB:
		{
			DES_cblock keyEncrypt, ivec;
			memset(keyEncrypt, 0, 8);

			if (key.length() <= 8) 
				memcpy(keyEncrypt, key.c_str(), key.length());
			else 
				memcpy(keyEncrypt, key.c_str(), 8);

			DES_key_schedule keySchedule;
			DES_set_key_unchecked(&keyEncrypt, &keySchedule);	

			memcpy(ivec, cbc_iv, sizeof(cbc_iv));

			unsigned char* outputText = new unsigned char[cleartext.length()];
			memset(outputText, 0, cleartext.length());

			const unsigned char* tmp = (const unsigned char*)cleartext.c_str();

			DES_cfb_encrypt(tmp, outputText, 8, cleartext.length(), &keySchedule, &ivec, DES_ENCRYPT);

			strCipherText = (char*)outputText;
			
			delete [] outputText;
		}
		break;
	case TRIPLE_ECB:
		{
			DES_cblock ke1, ke2, ke3;
			memset(ke1, 0, 8);
			memset(ke2, 0, 8);
			memset(ke2, 0, 8);

			if (key.length() >= 24) {
				memcpy(ke1, key.c_str(), 8);
				memcpy(ke2, key.c_str() + 8, 8);
				memcpy(ke3, key.c_str() + 16, 8);
			} else if (key.length() >= 16) {
				memcpy(ke1, key.c_str(), 8);
				memcpy(ke2, key.c_str() + 8, 8);
				memcpy(ke3, key.c_str() + 16, key.length() - 16);
			} else if (key.length() >= 8) {
				memcpy(ke1, key.c_str(), 8);
				memcpy(ke2, key.c_str() + 8, key.length() - 8);
				memcpy(ke3, key.c_str(), 8);
			} else {
				memcpy(ke1, key.c_str(), key.length());
				memcpy(ke2, key.c_str(), key.length());
				memcpy(ke3, key.c_str(), key.length());
			}

			DES_key_schedule ks1, ks2, ks3;
			DES_set_key_unchecked(&ke1, &ks1);
			DES_set_key_unchecked(&ke2, &ks2);
			DES_set_key_unchecked(&ke3, &ks3);

			const_DES_cblock inputText;
			DES_cblock outputText;
			vector<unsigned char> vecCiphertext;
			unsigned char tmp[8];

			for (int i = 0; i < cleartext.length() / 8; i ++) {
				memcpy(inputText, cleartext.c_str() + i * 8, 8);
				DES_ecb3_encrypt(&inputText, &outputText, &ks1, &ks2, &ks3, DES_ENCRYPT);
				memcpy(tmp, outputText, 8);

				for (int j = 0; j < 8; j++)
					vecCiphertext.push_back(tmp[j]);
			}

			if (cleartext.length() % 8 != 0) {
				int tmp1 = cleartext.length() / 8 * 8;
				int tmp2 = cleartext.length() - tmp1;
				memset(inputText, 0, 8);
				memcpy(inputText, cleartext.c_str() + tmp1, tmp2);

				DES_ecb3_encrypt(&inputText, &outputText, &ks1, &ks2, &ks3, DES_ENCRYPT);
				memcpy(tmp, outputText, 8);

				for (int j = 0; j < 8; j++)
					vecCiphertext.push_back(tmp[j]);
			}

			strCipherText.clear();
			strCipherText.assign(vecCiphertext.begin(), vecCiphertext.end());
		}
		break;
	case TRIPLE_CBC:
		{
			DES_cblock ke1, ke2, ke3, ivec;
			memset(ke1, 0, 8);
			memset(ke2, 0, 8);
			memset(ke2, 0, 8);

			if (key.length() >= 24) {
				memcpy(ke1, key.c_str(), 8);
				memcpy(ke2, key.c_str() + 8, 8);
				memcpy(ke3, key.c_str() + 16, 8);
			} else if (key.length() >= 16) {
				memcpy(ke1, key.c_str(), 8);
				memcpy(ke2, key.c_str() + 8, 8);
				memcpy(ke3, key.c_str() + 16, key.length() - 16);
			} else if (key.length() >= 8) {
				memcpy(ke1, key.c_str(), 8);
				memcpy(ke2, key.c_str() + 8, key.length() - 8);
				memcpy(ke3, key.c_str(), 8);
			} else {
				memcpy(ke1, key.c_str(), key.length());
				memcpy(ke2, key.c_str(), key.length());
				memcpy(ke3, key.c_str(), key.length());
			}

			DES_key_schedule ks1, ks2, ks3;
			DES_set_key_unchecked(&ke1, &ks1);
			DES_set_key_unchecked(&ke2, &ks2);
			DES_set_key_unchecked(&ke3, &ks3);

			memcpy(ivec, cbc_iv, sizeof(cbc_iv));

			int iLength = cleartext.length() % 8 ? (cleartext.length() / 8 + 1) * 8 : cleartext.length();
			unsigned char* tmp = new unsigned char[iLength + 16];
			memset(tmp, 0, iLength);

			DES_ede3_cbc_encrypt((const unsigned char*)cleartext.c_str(), tmp, cleartext.length()+1, &ks1, &ks2, &ks3, &ivec, DES_ENCRYPT);

			strCipherText = (char*)tmp;

			delete [] tmp;
		}
		break;
	}

	return strCipherText;
}

string DES_Decrypt(const string ciphertext, const string key, CRYPTO_MODE mode)
{
	string strClearText;

	switch (mode) {
	case GENERAL:
	case ECB:
		{
			DES_cblock keyEncrypt;
			memset(keyEncrypt, 0, 8);

			if (key.length() <= 8) 
				memcpy(keyEncrypt, key.c_str(), key.length());
			else 
				memcpy(keyEncrypt, key.c_str(), 8);

			DES_key_schedule keySchedule;
			DES_set_key_unchecked(&keyEncrypt, &keySchedule);	

			const_DES_cblock inputText;
			DES_cblock outputText;
			vector<unsigned char> vecCleartext;
			unsigned char tmp[8];

			for (int i = 0; i < ciphertext.length() / 8; i ++) {
				memcpy(inputText, ciphertext.c_str() + i * 8, 8);
				DES_ecb_encrypt(&inputText, &outputText, &keySchedule, DES_DECRYPT);
				memcpy(tmp, outputText, 8);

				for (int j = 0; j < 8; j++)
					vecCleartext.push_back(tmp[j]);
			}

			if (ciphertext.length() % 8 != 0) {
				int tmp1 = ciphertext.length() / 8 * 8;
				int tmp2 = ciphertext.length() - tmp1;
				memset(inputText, 0, 8);
				memcpy(inputText, ciphertext.c_str() + tmp1, tmp2);

				DES_ecb_encrypt(&inputText, &outputText, &keySchedule, DES_DECRYPT);
				memcpy(tmp, outputText, 8);

				for (int j = 0; j < 8; j++)
					vecCleartext.push_back(tmp[j]);
			}

			strClearText.clear();
			strClearText.assign(vecCleartext.begin(), vecCleartext.end());
		}
		break;
	case CBC:
		{
			DES_cblock keyEncrypt, ivec;
			memset(keyEncrypt, 0, 8);

			if (key.length() <= 8) 
				memcpy(keyEncrypt, key.c_str(), key.length());
			else 
				memcpy(keyEncrypt, key.c_str(), 8);

			DES_key_schedule keySchedule;
			DES_set_key_unchecked(&keyEncrypt, &keySchedule);	

			memcpy(ivec, cbc_iv, sizeof(cbc_iv));

			int iLength = ciphertext.length() % 8 ? (ciphertext.length() / 8 + 1) * 8 : ciphertext.length();
			unsigned char* tmp = new unsigned char[iLength];
			memset(tmp, 0, iLength);

			DES_ncbc_encrypt((const unsigned char*)ciphertext.c_str(), tmp, ciphertext.length()+1, &keySchedule, &ivec, DES_DECRYPT);

			strClearText = (char*)tmp;

			delete [] tmp;
		}
		break;
	case CFB:
		{
			DES_cblock keyEncrypt, ivec;
			memset(keyEncrypt, 0, 8);

			if (key.length() <= 8) 
				memcpy(keyEncrypt, key.c_str(), key.length());
			else 
				memcpy(keyEncrypt, key.c_str(), 8);

			DES_key_schedule keySchedule;
			DES_set_key_unchecked(&keyEncrypt, &keySchedule);	

			memcpy(ivec, cbc_iv, sizeof(cbc_iv));

			unsigned char* outputText = new unsigned char[ciphertext.length()];
			memset(outputText, 0, ciphertext.length());

			const unsigned char* tmp = (const unsigned char*)ciphertext.c_str();

			DES_cfb_encrypt(tmp, outputText, 8, 32/*ciphertext.length() - 16*/, &keySchedule, &ivec, DES_DECRYPT);

			strClearText = (char*)outputText;

			delete [] outputText;
		}
		break;
	case TRIPLE_ECB:
		{
			DES_cblock ke1, ke2, ke3;
			memset(ke1, 0, 8);
			memset(ke2, 0, 8);
			memset(ke2, 0, 8);

			if (key.length() >= 24) {
				memcpy(ke1, key.c_str(), 8);
				memcpy(ke2, key.c_str() + 8, 8);
				memcpy(ke3, key.c_str() + 16, 8);
			} else if (key.length() >= 16) {
				memcpy(ke1, key.c_str(), 8);
				memcpy(ke2, key.c_str() + 8, 8);
				memcpy(ke3, key.c_str() + 16, key.length() - 16);
			} else if (key.length() >= 8) {
				memcpy(ke1, key.c_str(), 8);
				memcpy(ke2, key.c_str() + 8, key.length() - 8);
				memcpy(ke3, key.c_str(), 8);
			} else {
				memcpy(ke1, key.c_str(), key.length());
				memcpy(ke2, key.c_str(), key.length());
				memcpy(ke3, key.c_str(), key.length());
			}

			DES_key_schedule ks1, ks2, ks3;
			DES_set_key_unchecked(&ke1, &ks1);
			DES_set_key_unchecked(&ke2, &ks2);
			DES_set_key_unchecked(&ke3, &ks3);

			const_DES_cblock inputText;
			DES_cblock outputText;
			vector<unsigned char> vecCleartext;
			unsigned char tmp[8];

			for (int i = 0; i < ciphertext.length() / 8; i ++) {
				memcpy(inputText, ciphertext.c_str() + i * 8, 8);
				DES_ecb3_encrypt(&inputText, &outputText, &ks1, &ks2, &ks3, DES_DECRYPT);
				memcpy(tmp, outputText, 8);

				for (int j = 0; j < 8; j++)
					vecCleartext.push_back(tmp[j]);
			}

			if (ciphertext.length() % 8 != 0) {
				int tmp1 = ciphertext.length() / 8 * 8;
				int tmp2 = ciphertext.length() - tmp1;
				memset(inputText, 0, 8);
				memcpy(inputText, ciphertext.c_str() + tmp1, tmp2);

				DES_ecb3_encrypt(&inputText, &outputText, &ks1, &ks2, &ks3, DES_DECRYPT);
				memcpy(tmp, outputText, 8);

				for (int j = 0; j < 8; j++)
					vecCleartext.push_back(tmp[j]);
			}

			strClearText.clear();
			strClearText.assign(vecCleartext.begin(), vecCleartext.end());
		}
		break;
	case TRIPLE_CBC:
		{
			DES_cblock ke1, ke2, ke3, ivec;
			memset(ke1, 0, 8);
			memset(ke2, 0, 8);
			memset(ke2, 0, 8);

			if (key.length() >= 24) {
				memcpy(ke1, key.c_str(), 8);
				memcpy(ke2, key.c_str() + 8, 8);
				memcpy(ke3, key.c_str() + 16, 8);
			} else if (key.length() >= 16) {
				memcpy(ke1, key.c_str(), 8);
				memcpy(ke2, key.c_str() + 8, 8);
				memcpy(ke3, key.c_str() + 16, key.length() - 16);
			} else if (key.length() >= 8) {
				memcpy(ke1, key.c_str(), 8);
				memcpy(ke2, key.c_str() + 8, key.length() - 8);
				memcpy(ke3, key.c_str(), 8);
			} else {
				memcpy(ke1, key.c_str(), key.length());
				memcpy(ke2, key.c_str(), key.length());
				memcpy(ke3, key.c_str(), key.length());
			}

			DES_key_schedule ks1, ks2, ks3;
			DES_set_key_unchecked(&ke1, &ks1);
			DES_set_key_unchecked(&ke2, &ks2);
			DES_set_key_unchecked(&ke3, &ks3);

			memcpy(ivec, cbc_iv, sizeof(cbc_iv));

			int iLength = ciphertext.length() % 8 ? (ciphertext.length() / 8 + 1) * 8 : ciphertext.length();
			unsigned char* tmp = new unsigned char[iLength];
			memset(tmp, 0, iLength);

			DES_ede3_cbc_encrypt((const unsigned char*)ciphertext.c_str(), tmp, ciphertext.length()+1, &ks1, &ks2, &ks3, &ivec, DES_DECRYPT);

			strClearText = (char*)tmp;

			delete [] tmp;
		}
		break;
	}

	return strClearText;
}

bool DES_Test()
{
	DES_cblock key;
	//DES_string_to_key("pass", &key);
	string str = "beijingchina";
	memcpy(key, str.c_str(), 8);
	DES_key_schedule schedule;
	DES_set_key_unchecked(&key, &schedule); 

	const_DES_cblock input = "01234";
	DES_cblock output;

	//printf("cleartext:%s\n ", input);

	DES_ecb_encrypt(&input, &output, &schedule, DES_ENCRYPT);
	//printf("Encrypted!\n ");

	printf("ciphertext:");
	int i;
	//for (i = 0; i < sizeof(input); i++)
	//	printf("%c", output[i]);
	//printf(" \n");
	printf("%s\n", output);
	memset(input, 0, 8);

	DES_ecb_encrypt(&output, &input, &schedule, DES_DECRYPT);
	//printf("Decrypted! ");
	printf("cleartext:%s \n", input);

	return true;
}