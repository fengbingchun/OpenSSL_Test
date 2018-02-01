#include "cryptotest.h"
#include <iostream>
#include <string>

using namespace std;

void test_DES();

int main(int argc, char* argv[])
{
	test_DES();
	cout<<"ok!!!"<<endl;

	return 0;
}

void test_RSA()
{
	// Blog: http://blog.csdn.net/fengbingchun/article/details/43638013
	//string strKey[2] = {};//[0]:public key; [1]:private key 
	//GenerateRSAKey(strKey);
	//cout<<"public key:"<<endl<<strKey[0]<<endl;
	//cout<<"private key:"<<endl<<strKey[1]<<endl;

	string cleartext = "中国北京12345$abcde%ABCDE@！！！!";

	if (cleartext.length() > 256) {
		cout<<"cleartext too length!!!"<<endl;
		return ;
	}

	//RSA_test1(cleartext);
	RSA_test2(cleartext);
}

void test_MD5()
{
	// Blog: http://blog.csdn.net/fengbingchun/article/details/42978603
	string strSrc[7] = {"", "a", "abc", "message digest", "abcdefghijklmnopqrstuvwxyz",
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
		"12345678901234567890123456789012345678901234567890123456789012345678901234567890"};

	string strDigest[7] = {"d41d8cd98f00b204e9800998ecf8427e",
		"0cc175b9c0f1b6a831c399e269772661",
		"900150983cd24fb0d6963f7d28e17f72",
		"f96b697d7cb7938d525a2f31aaf161d0",
		"c3fcd3d76192e4007dfb496cca67e13b",
		"d174ab98d277d9f5a5611c2c9f419d9f",
		"57edf4a22be3c955ac49da2e2107b67a"};

	for (int i = 0; i < 7; i++) {
		string str = MD5_Digest(strSrc[i]);
		cout<<str<<endl;

		if (strcmp(strDigest[i].c_str(), str.c_str()) != 0)
			cout<<"i = "<<i<<" MD5 error!"<<endl;
	}
}

void test_DES()
{
	// Blog: http://blog.csdn.net/fengbingchun/article/details/42611875
	string cleartext = "中国北京12345$abcde%ABCDE@！！！!";
	string ciphertext = "";
	string key = "beijingchina1234567890ABCDEFGH!!!";

	CRYPTO_MODE mode = CBC;

	ciphertext = DES_Encrypt(cleartext, key, mode);
	string decrypt = DES_Decrypt(ciphertext, key, mode);

	cout<<"src cleartext: "<<cleartext<<endl;
	cout<<"genarate ciphertext: "<<ciphertext<<endl;
	cout<<"src ciphertext: "<<ciphertext<<endl;
	cout<<"genarate cleartext: "<<decrypt<<endl;

	if (strcmp(cleartext.c_str(), decrypt.c_str()) == 0)
		cout<<"DES crypto ok!!!"<<endl;
	else
		cout<<"DES crypto error!!!"<<endl;
}

void test_RC4()
{
	// Blog: http://blog.csdn.net/fengbingchun/article/details/42929883
	string cleartext = "中国北京12345$abcde%ABCDE@！！！";
	string ciphertext = "";
	string key = "beijingchina1234567890ABCDEFGH!!!";

	ciphertext = RC4_Encrypt(cleartext, key);
	string decrypt = RC4_Decrypt(ciphertext, key);

	cout<<"src cleartext: "<<cleartext<<endl;
	cout<<"genarate ciphertext: "<<ciphertext<<endl;
	cout<<"src ciphertext: "<<ciphertext<<endl;
	cout<<"genarate cleartext: "<<decrypt<<endl;

	if (strcmp(cleartext.c_str(), decrypt.c_str()) == 0)
		cout<<"RC4 crypto ok!!!"<<endl;
	else
		cout<<"RC4 crypto error!!!"<<endl;
}

