#ifndef FBC_OPENSSL_TEST_FUNSET_HPP_
#define FBC_OPENSSL_TEST_FUNSET_HPP_

// test b64.c interface
int test_b64_base64();

// test cppcodec interface
int test_ccpcodec_base64_rfc4648();

// test openssl interface
typedef enum {
	GENERAL = 0,
	ECB,
	CBC,
	CFB,
	OFB,
	TRIPLE_ECB,
	TRIPLE_CBC
} CRYPTO_MODE;

int test_openssl_des();
int test_openssl_rc4();
int test_openssl_md5();
int test_openssl_rsa();


#endif // FBC_OPENSSL_TEST_FUNSET_HPP_

