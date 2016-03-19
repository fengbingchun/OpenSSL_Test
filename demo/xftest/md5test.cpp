#include <iostream>
#include <string>
#include <vector>
#include <cstdio>
#include <iomanip>
#include <stdlib.h>
#include <openssl/md5.h>

#include "cryptotest.h"

using namespace std;

string MD5_Digest(const string cleartext)
{
	string strDigest;
	unsigned char tmp[16] = {0};

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

	for(int i = 0; i < 16; i++) 
		sprintf(&(tmp1[i*2]), "%02x", tmp[i]);
		//cout<<hex<<setw(2)<<setfill('0')<<(int)tmp[i]; 

	strDigest = (char*)tmp1;

	delete [] tmp1;

	return strDigest;
}