#include "funset.hpp"
#include <string.h>
#include <string>
#include <vector>
#include <openssl/des.h>
#include <openssl/rc4.h>
#include <openssl/md5.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <b64/b64.h>

//////////////////////////// DES ///////////////////////////////
// Blog: https://blog.csdn.net/fengbingchun/article/details/42611875
namespace {
unsigned char cbc_iv[] = { '0', '1', 'A', 'B', 'a', 'b', '9', '8' };

std::string des_encrypt(const std::string& cleartext, const std::string& key, CRYPTO_MODE mode)
{
	std::string strCipherText;

	switch (mode) {
	case GENERAL:
	case ECB: {
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
		std::vector<unsigned char> vecCiphertext;
		unsigned char tmp[8];

		for (int i = 0; i < cleartext.length() / 8; i++) {
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
	case CBC: {
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

		DES_ncbc_encrypt((const unsigned char*)cleartext.c_str(), tmp, cleartext.length() + 1, &keySchedule, &ivec, DES_ENCRYPT);

		// strClearText = (char*)tmp; 这种写法有问题，从unsigned char*强转为char*，如果遇到内存中间存在0x0，
		// strClearText实际是截断的，应该做个base64加密运算再返回，解密时数据才是完整的
		// strCipherText = (char*)tmp;
		strCipherText = reinterpret_cast<char*>(tmp);

		delete[] tmp;
	}
		break;
	case CFB: {
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

		delete[] outputText;
	}
		break;
	case TRIPLE_ECB: {
		DES_cblock ke1, ke2, ke3;
		memset(ke1, 0, 8);
		memset(ke2, 0, 8);
		memset(ke2, 0, 8);

		if (key.length() >= 24) {
			memcpy(ke1, key.c_str(), 8);
			memcpy(ke2, key.c_str() + 8, 8);
			memcpy(ke3, key.c_str() + 16, 8);
		}
		else if (key.length() >= 16) {
			memcpy(ke1, key.c_str(), 8);
			memcpy(ke2, key.c_str() + 8, 8);
			memcpy(ke3, key.c_str() + 16, key.length() - 16);
		}
		else if (key.length() >= 8) {
			memcpy(ke1, key.c_str(), 8);
			memcpy(ke2, key.c_str() + 8, key.length() - 8);
			memcpy(ke3, key.c_str(), 8);
		}
		else {
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
		std::vector<unsigned char> vecCiphertext;
		unsigned char tmp[8];

		for (int i = 0; i < cleartext.length() / 8; i++) {
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
	case TRIPLE_CBC: {
		DES_cblock ke1, ke2, ke3, ivec;
		memset(ke1, 0, 8);
		memset(ke2, 0, 8);
		memset(ke2, 0, 8);

		if (key.length() >= 24) {
			memcpy(ke1, key.c_str(), 8);
			memcpy(ke2, key.c_str() + 8, 8);
			memcpy(ke3, key.c_str() + 16, 8);
		}
		else if (key.length() >= 16) {
			memcpy(ke1, key.c_str(), 8);
			memcpy(ke2, key.c_str() + 8, 8);
			memcpy(ke3, key.c_str() + 16, key.length() - 16);
		}
		else if (key.length() >= 8) {
			memcpy(ke1, key.c_str(), 8);
			memcpy(ke2, key.c_str() + 8, key.length() - 8);
			memcpy(ke3, key.c_str(), 8);
		}
		else {
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

		DES_ede3_cbc_encrypt((const unsigned char*)cleartext.c_str(), tmp, cleartext.length() + 1, &ks1, &ks2, &ks3, &ivec, DES_ENCRYPT);

		strCipherText = (char*)tmp;

		delete[] tmp;
	}
		break;
	default:
		fprintf(stderr, "Error: DES don't support this mode encrypt: %d\n", mode);
	}

	return strCipherText;
}

std::string des_decrypt(const std::string& ciphertext, const std::string& key, CRYPTO_MODE mode)
{
	std::string strClearText;

	switch (mode) {
	case GENERAL:
	case ECB: {
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
	std::vector<unsigned char> vecCleartext;
	unsigned char tmp[8];

	for (int i = 0; i < ciphertext.length() / 8; i++) {
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
	case CBC: {
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
		unsigned char* tmp = new unsigned char[iLength + 16];
		memset(tmp, 0, iLength);

		DES_ncbc_encrypt((const unsigned char*)ciphertext.c_str(), tmp, ciphertext.length() + 1, &keySchedule, &ivec, DES_DECRYPT);

		strClearText = (char*)tmp;

		delete[] tmp;
	}
		break;
	case CFB: {
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

		delete[] outputText;
	}
		break;
	case TRIPLE_ECB: {
		DES_cblock ke1, ke2, ke3;
		memset(ke1, 0, 8);
		memset(ke2, 0, 8);
		memset(ke2, 0, 8);

		if (key.length() >= 24) {
			memcpy(ke1, key.c_str(), 8);
			memcpy(ke2, key.c_str() + 8, 8);
			memcpy(ke3, key.c_str() + 16, 8);
		}
		else if (key.length() >= 16) {
			memcpy(ke1, key.c_str(), 8);
			memcpy(ke2, key.c_str() + 8, 8);
			memcpy(ke3, key.c_str() + 16, key.length() - 16);
		}
		else if (key.length() >= 8) {
			memcpy(ke1, key.c_str(), 8);
			memcpy(ke2, key.c_str() + 8, key.length() - 8);
			memcpy(ke3, key.c_str(), 8);
		}
		else {
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
		std::vector<unsigned char> vecCleartext;
		unsigned char tmp[8];

		for (int i = 0; i < ciphertext.length() / 8; i++) {
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
	case TRIPLE_CBC: {
		DES_cblock ke1, ke2, ke3, ivec;
		memset(ke1, 0, 8);
		memset(ke2, 0, 8);
		memset(ke2, 0, 8);

		if (key.length() >= 24) {
			memcpy(ke1, key.c_str(), 8);
			memcpy(ke2, key.c_str() + 8, 8);
			memcpy(ke3, key.c_str() + 16, 8);
		}
		else if (key.length() >= 16) {
			memcpy(ke1, key.c_str(), 8);
			memcpy(ke2, key.c_str() + 8, 8);
			memcpy(ke3, key.c_str() + 16, key.length() - 16);
		}
		else if (key.length() >= 8) {
			memcpy(ke1, key.c_str(), 8);
			memcpy(ke2, key.c_str() + 8, key.length() - 8);
			memcpy(ke3, key.c_str(), 8);
		}
		else {
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

		DES_ede3_cbc_encrypt((const unsigned char*)ciphertext.c_str(), tmp, ciphertext.length() + 1, &ks1, &ks2, &ks3, &ivec, DES_DECRYPT);

		strClearText = (char*)tmp;

		delete[] tmp;
	}
		break;
	default:
		fprintf(stderr, "Error: DES don't support this mode decrypt: %d\n", mode);
	}

	return strClearText;
}

} // namespace

int test_openssl_des()
{
	const std::string cleartext = "中国北京12345$abcde%ABCDE！！！!";
	const std::string key = "beijingchina1234567890ABCDEFGH!!!";

	char* cleartext_encode = b64_encode((const unsigned char*)cleartext.c_str(), cleartext.length());
	std::string str_encode(cleartext_encode);
	free(cleartext_encode);

	CRYPTO_MODE mode = CBC;
	std::string ciphertext = des_encrypt(str_encode, key, mode);
	std::string decrypt = des_decrypt(ciphertext, key, mode);
	unsigned char* ciphertext_decode = b64_decode(decrypt.c_str(), decrypt.length());
	std::string str_decode((char*)ciphertext_decode);
	free(ciphertext_decode);

	fprintf(stdout, "src cleartext: %s, size: %d\n", cleartext.c_str(), cleartext.length());
	fprintf(stdout, "genarate ciphertext: %s, size: %d\n", ciphertext.c_str(), ciphertext.length());
	fprintf(stdout, "dst cleartext: %s, size: %d\n", str_decode.c_str(), str_decode.length());

	if (strcmp(cleartext.c_str(), str_decode.c_str()) == 0) {
		fprintf(stdout, "DES decrypt success\n");
		return 0;
	} else {
		fprintf(stderr, "DES decrypt fail\n");
		return -1;
	}	
}

//////////////////////////// RC4 ///////////////////////////////
// Blog: https://blog.csdn.net/fengbingchun/article/details/42929883
namespace {
std::string RC4_Encrypt(const std::string& cleartext, const std::string& key)
{
	RC4_KEY rc4key;
	unsigned char* tmp = new unsigned char[cleartext.length()];
	memset(tmp, 0, cleartext.length());

	RC4_set_key(&rc4key, key.length(), (const unsigned char*)key.c_str());
	RC4(&rc4key, cleartext.length(), (const unsigned char*)cleartext.c_str(), tmp);

	std::string str = std::string((char*)tmp);

	delete[] tmp;
	return str;
}

std::string RC4_Decrypt(const std::string& ciphertext, const std::string& key)
{
	RC4_KEY rc4key;
	unsigned char* tmp = new unsigned char[ciphertext.length()];
	memset(tmp, 0, ciphertext.length());

	RC4_set_key(&rc4key, key.length(), (const unsigned char*)key.c_str());
	RC4(&rc4key, ciphertext.length(), (const unsigned char*)ciphertext.c_str(), tmp);

	std::string str = std::string((char*)tmp);

	delete[] tmp;
	return str;
}

} // namespace

int test_openssl_rc4()
{
	const std::string cleartext = "中国北京12345$abcde%ABCDE@！！！!";
	const std::string key = "beijingchina1234567890ABCDEFGH!!!";

	char* cleartext_encode = b64_encode((const unsigned char*)cleartext.c_str(), cleartext.length());
	std::string str_encode(cleartext_encode);
	free(cleartext_encode);

	std::string ciphertext = RC4_Encrypt(str_encode, key);
	std::string decrypt = RC4_Decrypt(ciphertext, key);
	unsigned char* ciphertext_decode = b64_decode(decrypt.c_str(), decrypt.length());
	std::string str_decode((char*)ciphertext_decode);
	free(ciphertext_decode);

	fprintf(stdout, "src cleartext: %s\n", cleartext.c_str());
	fprintf(stdout, "genarate ciphertext: %s\n", ciphertext.c_str());
	fprintf(stdout, "dst cleartext: %s\n", str_decode.c_str());

	if (strcmp(cleartext.c_str(), str_decode.c_str()) == 0) {
		fprintf(stdout, "RC4 decrypt success\n");
		return 0;
	} else {
		fprintf(stderr, "RC4 decrypt fail\n");
		return -1;
	}
}

////////////////////////////// MD5 /////////////////////////////
// Blog: https://blog.csdn.net/fengbingchun/article/details/42978603
namespace {
std::string MD5_Digest(const std::string& cleartext)
{
	std::string strDigest;
	unsigned char tmp[16] = { 0 };

#if 0
	MD5((const unsigned char*)cleartext.c_str(), cleartext.length(), tmp);
#else
	MD5_CTX c;
	MD5_Init(&c);
	MD5_Update(&c, cleartext.c_str(), cleartext.length());
	MD5_Final(tmp, &c);
#endif

	char* tmp1 = new char[32 + 1];
	memset(tmp1, 0, 32 + 1);

	for (int i = 0; i < 16; i++)
		sprintf(&(tmp1[i * 2]), "%02x", tmp[i]);
	//cout<<hex<<setw(2)<<setfill('0')<<(int)tmp[i]; 

	strDigest = (char*)tmp1;

	delete[] tmp1;
	return strDigest;
}

} // namespace

int test_openssl_md5()
{
	std::string strSrc[7] = {
		"",
		"a",
		"abc",
		"message digest",
		"abcdefghijklmnopqrstuvwxyz",
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
		"12345678901234567890123456789012345678901234567890123456789012345678901234567890" };
	std::string strDigest[7] = { 
		"d41d8cd98f00b204e9800998ecf8427e",
		"0cc175b9c0f1b6a831c399e269772661",
		"900150983cd24fb0d6963f7d28e17f72",
		"f96b697d7cb7938d525a2f31aaf161d0",
		"c3fcd3d76192e4007dfb496cca67e13b",
		"d174ab98d277d9f5a5611c2c9f419d9f",
		"57edf4a22be3c955ac49da2e2107b67a" };

	for (int i = 0; i < 7; i++) {
		std::string str = MD5_Digest(strSrc[i]);
		fprintf(stdout, "str: %s\n", str.c_str());

		if (strcmp(strDigest[i].c_str(), str.c_str()) != 0) {
			fprintf(stderr, "i: %d, MD5 error\n", i);
			return -1;
		}
	}

	return 0;
}

//////////////////////////// RSA ///////////////////////////////
// Blog: https://blog.csdn.net/fengbingchun/article/details/43638013
namespace {
const int KEY_LENGTH = 2048;
const int padding = RSA_PKCS1_PADDING;
const unsigned long PUB_EXP = 3;

void Generate_RSA_Key(std::string& public_key, std::string& private_key)
{
	size_t pri_len;          // Length of private key
	size_t pub_len;          // Length of public key
	char *pri_key = NULL;           // Private key
	char *pub_key = NULL;           // Public key

	RSA* keypair = RSA_generate_key(KEY_LENGTH, RSA_3, NULL, NULL);

	BIO *pri = BIO_new(BIO_s_mem());
	BIO *pub = BIO_new(BIO_s_mem());

	PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);
	PEM_write_bio_RSAPublicKey(pub, keypair);

	pri_len = BIO_pending(pri);
	pub_len = BIO_pending(pub);

	pri_key = new char[pri_len + 1];
	pub_key = new char[pub_len + 1];

	BIO_read(pri, pri_key, pri_len);
	BIO_read(pub, pub_key, pub_len);

	pri_key[pri_len] = '\0';
	pub_key[pub_len] = '\0';

	public_key = std::string(pub_key, pub_len+1);
	private_key = std::string(pri_key, pri_len+1);

	RSA_free(keypair);
	BIO_free_all(pub);
	BIO_free_all(pri);
	delete[] pri_key;
	delete[] pub_key;
}

RSA* createRSA(const unsigned char* key, int flag)
{
	RSA *rsa = NULL;
	BIO *keybio;
	keybio = BIO_new_mem_buf((unsigned char*)key, -1);

	if (keybio == NULL) {
		fprintf(stderr, "Error: fail to create key BIO\n");
		return nullptr;
	}

	if (flag)
		rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
	else
		rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);

	if (rsa == NULL) {
		fprintf(stderr, "Error: fail to create RSA\n");
		return nullptr;
	}

	return rsa;
}

int public_encrypt(const unsigned char* data, int data_len, const unsigned char* key, unsigned char* encrypted)
{
	RSA * rsa = createRSA(key, 1);
	int result = RSA_public_encrypt(data_len, data, encrypted, rsa, padding);
	return result;
}

int private_decrypt(const unsigned char* enc_data, int data_len, const unsigned char* key, unsigned char* decrypted)
{
	RSA * rsa = createRSA(key, 0);
	int  result = RSA_private_decrypt(data_len, enc_data, decrypted, rsa, padding);
	return result;
}

int private_encrypt(const unsigned char* data, int data_len, const unsigned char* key, unsigned char* encrypted)
{
	RSA * rsa = createRSA(key, 0);
	int result = RSA_private_encrypt(data_len, data, encrypted, rsa, padding);
	return result;
}

int public_decrypt(const unsigned char* enc_data, int data_len, const unsigned char* key, unsigned char* decrypted)
{
	RSA * rsa = createRSA(key, 1);
	int  result = RSA_public_decrypt(data_len, enc_data, decrypted, rsa, padding);
	return result;
}

} // namespace

int test_openssl_rsa()
{
	std::vector<std::string> strKey(2);//[0]:public key; [1]:private key 
	Generate_RSA_Key(strKey[0], strKey[1]);
	fprintf(stdout, "public key:\n%s\n", strKey[0].c_str());
	fprintf(stdout, "private key:\n%s\n", strKey[1].c_str());

	strKey[0] = "-----BEGIN PUBLIC KEY-----\n" \
		"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy8Dbv8prpJ/0kKhlGeJY\n" \
		"ozo2t60EG8L0561g13R29LvMR5hyvGZlGJpmn65+A4xHXInJYiPuKzrKUnApeLZ+\n" \
		"vw1HocOAZtWK0z3r26uA8kQYOKX9Qt/DbCdvsF9wF8gRK0ptx9M6R13NvBxvVQAp\n" \
		"fc9jB9nTzphOgM4JiEYvlV8FLhg9yZovMYd6Wwf3aoXK891VQxTr/kQYoq1Yp+68\n" \
		"i6T4nNq7NWC+UNVjQHxNQMQMzU6lWCX8zyg3yH88OAQkUXIXKfQ+NkvYQ1cxaMoV\n" \
		"PpY72+eVthKzpMeyHkBn7ciumk5qgLTEJAfWZpe4f4eFZj/Rc8Y8Jj2IS5kVPjUy\n" \
		"wQIDAQAB\n" \
		"-----END PUBLIC KEY-----\n";
	strKey[1] = "-----BEGIN RSA PRIVATE KEY-----\n"\
		"MIIEowIBAAKCAQEAy8Dbv8prpJ/0kKhlGeJYozo2t60EG8L0561g13R29LvMR5hy\n"\
		"vGZlGJpmn65+A4xHXInJYiPuKzrKUnApeLZ+vw1HocOAZtWK0z3r26uA8kQYOKX9\n"\
		"Qt/DbCdvsF9wF8gRK0ptx9M6R13NvBxvVQApfc9jB9nTzphOgM4JiEYvlV8FLhg9\n"\
		"yZovMYd6Wwf3aoXK891VQxTr/kQYoq1Yp+68i6T4nNq7NWC+UNVjQHxNQMQMzU6l\n"\
		"WCX8zyg3yH88OAQkUXIXKfQ+NkvYQ1cxaMoVPpY72+eVthKzpMeyHkBn7ciumk5q\n"\
		"gLTEJAfWZpe4f4eFZj/Rc8Y8Jj2IS5kVPjUywQIDAQABAoIBADhg1u1Mv1hAAlX8\n"\
		"omz1Gn2f4AAW2aos2cM5UDCNw1SYmj+9SRIkaxjRsE/C4o9sw1oxrg1/z6kajV0e\n"\
		"N/t008FdlVKHXAIYWF93JMoVvIpMmT8jft6AN/y3NMpivgt2inmmEJZYNioFJKZG\n"\
		"X+/vKYvsVISZm2fw8NfnKvAQK55yu+GRWBZGOeS9K+LbYvOwcrjKhHz66m4bedKd\n"\
		"gVAix6NE5iwmjNXktSQlJMCjbtdNXg/xo1/G4kG2p/MO1HLcKfe1N5FgBiXj3Qjl\n"\
		"vgvjJZkh1as2KTgaPOBqZaP03738VnYg23ISyvfT/teArVGtxrmFP7939EvJFKpF\n"\
		"1wTxuDkCgYEA7t0DR37zt+dEJy+5vm7zSmN97VenwQJFWMiulkHGa0yU3lLasxxu\n"\
		"m0oUtndIjenIvSx6t3Y+agK2F3EPbb0AZ5wZ1p1IXs4vktgeQwSSBdqcM8LZFDvZ\n"\
		"uPboQnJoRdIkd62XnP5ekIEIBAfOp8v2wFpSfE7nNH2u4CpAXNSF9HsCgYEA2l8D\n"\
		"JrDE5m9Kkn+J4l+AdGfeBL1igPF3DnuPoV67BpgiaAgI4h25UJzXiDKKoa706S0D\n"\
		"4XB74zOLX11MaGPMIdhlG+SgeQfNoC5lE4ZWXNyESJH1SVgRGT9nBC2vtL6bxCVV\n"\
		"WBkTeC5D6c/QXcai6yw6OYyNNdp0uznKURe1xvMCgYBVYYcEjWqMuAvyferFGV+5\n"\
		"nWqr5gM+yJMFM2bEqupD/HHSLoeiMm2O8KIKvwSeRYzNohKTdZ7FwgZYxr8fGMoG\n"\
		"PxQ1VK9DxCvZL4tRpVaU5Rmknud9hg9DQG6xIbgIDR+f79sb8QjYWmcFGc1SyWOA\n"\
		"SkjlykZ2yt4xnqi3BfiD9QKBgGqLgRYXmXp1QoVIBRaWUi55nzHg1XbkWZqPXvz1\n"\
		"I3uMLv1jLjJlHk3euKqTPmC05HoApKwSHeA0/gOBmg404xyAYJTDcCidTg6hlF96\n"\
		"ZBja3xApZuxqM62F6dV4FQqzFX0WWhWp5n301N33r0qR6FumMKJzmVJ1TA8tmzEF\n"\
		"yINRAoGBAJqioYs8rK6eXzA8ywYLjqTLu/yQSLBn/4ta36K8DyCoLNlNxSuox+A5\n"\
		"w6z2vEfRVQDq4Hm4vBzjdi3QfYLNkTiTqLcvgWZ+eX44ogXtdTDO7c+GeMKWz4XX\n"\
		"uJSUVL5+CVjKLjZEJ6Qc2WZLl94xSwL71E41H4YciVnSCQxVc4Jw\n"\
		"-----END RSA PRIVATE KEY-----\n";

	std::string cleartext = "中国北京12345$abcde%ABCDE@！！！!";

	unsigned char  encrypted[4098] = {};
	unsigned char decrypted[4098] = {};

	int encrypted_length = public_encrypt((const unsigned char*)cleartext.c_str(), cleartext.length(), (const unsigned char*)strKey[0].c_str(), encrypted);
	if (encrypted_length == -1) {
		fprintf(stderr, "Error: fail to public key encrypt\n");
		return -1;
	}
	fprintf(stdout, "Encrypted length = %d\n", encrypted_length);

	int decrypted_length = private_decrypt(encrypted, encrypted_length, (const unsigned char*)strKey[1].c_str(), decrypted);
	if (decrypted_length == -1) {
		fprintf(stderr, "Error: fail to private key decrypt\n");
		return -1;
	}
	fprintf(stdout, "Decrypted Length = %d\n", decrypted_length);
	fprintf(stdout, "Decrypted Text = %s\n", decrypted);
	
	encrypted_length = private_encrypt((const unsigned char*)cleartext.c_str(), cleartext.length(), (const unsigned char*)strKey[1].c_str(), encrypted);
	if (encrypted_length == -1) {
		fprintf(stderr, "Error: fail to private key encrypt\n");
		return -1;
	}
	fprintf(stdout, "Encrypted length = %d\n", encrypted_length);

	decrypted_length = public_decrypt(encrypted, encrypted_length, (const unsigned char*)strKey[0].c_str(), decrypted);
	if (decrypted_length == -1) {
		fprintf(stderr, "Error: fail to public key decrypt\n");
		return -1;
	}
	fprintf(stdout, "Decrypted Length = %d\n", decrypted_length);
	fprintf(stdout, "Decrypted Text = %s \n", decrypted);

	return 0;
}
