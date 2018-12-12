#ifndef FBC_OPENSSL_TEST_FUNSET_HPP_
#define FBC_OPENSSL_TEST_FUNSET_HPP_

typedef enum {
	GENERAL = 0,
	ECB,
	CBC,
	CFB,
	OFB,
	TRIPLE_ECB,
	TRIPLE_CBC
} CRYPTO_MODE;

int test_des();
int test_rc4();
int test_md5();
int test_rsa();


#endif // FBC_OPENSSL_TEST_FUNSET_HPP_

