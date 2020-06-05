#ifndef FBC_OPENSSL_TEST_FUNSET_HPP_
#define FBC_OPENSSL_TEST_FUNSET_HPP_

#include <openssl/asn1.h>
#include <openssl/asn1t.h>

// bearssl
int test_bearssl_1();

// socket
int test_select_1();

// test libcurl interface
int test_curl_download_image_1();

// test http-parser interface
int test_http_parser();
int test_http_parser_url();

// test b64.c interface
int test_b64_base64();

// test cppcodec interface
int test_cppcodec_base64_rfc4648();

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

// crypto/rsa/rsa_local.h: struct rsa_st
typedef struct RSA_PRIVATE_KEY_st {
	ASN1_INTEGER* version;
	ASN1_INTEGER* n; // modulus, n = p * q
	ASN1_INTEGER* e; // publicExponent
	ASN1_INTEGER* d; // privateExponent
	ASN1_INTEGER* p; // prime1
	ASN1_INTEGER* q; // prime2
	ASN1_INTEGER* exp1; // dmp1, exponent1, = d mod (p − 1)
	ASN1_INTEGER* exp2; // dmq1, exponent2, = d mod (q − 1)
	ASN1_INTEGER* coeff; // iqmp, coefficient, = (inverse of q) mod p
} RSA_PRIVATE_KEY;

typedef struct RSA_PUBLIC_KEY_st {
	ASN1_INTEGER* n; // modulus, n = p * q
	ASN1_INTEGER* e; // publicExponent
} RSA_PUBLIC_KEY;

// general function
namespace {

DECLARE_ASN1_FUNCTIONS(RSA_PRIVATE_KEY);
ASN1_SEQUENCE(RSA_PRIVATE_KEY) = {
	ASN1_SIMPLE(RSA_PRIVATE_KEY, version, ASN1_INTEGER),
	ASN1_SIMPLE(RSA_PRIVATE_KEY, n, ASN1_INTEGER),
	ASN1_SIMPLE(RSA_PRIVATE_KEY, e, ASN1_INTEGER),
	ASN1_SIMPLE(RSA_PRIVATE_KEY, d, ASN1_INTEGER),
	ASN1_SIMPLE(RSA_PRIVATE_KEY, p, ASN1_INTEGER),
	ASN1_SIMPLE(RSA_PRIVATE_KEY, q, ASN1_INTEGER),
	ASN1_SIMPLE(RSA_PRIVATE_KEY, exp1, ASN1_INTEGER),
	ASN1_SIMPLE(RSA_PRIVATE_KEY, exp2, ASN1_INTEGER),
	ASN1_SIMPLE(RSA_PRIVATE_KEY, coeff, ASN1_INTEGER)
} ASN1_SEQUENCE_END(RSA_PRIVATE_KEY)
IMPLEMENT_ASN1_FUNCTIONS(RSA_PRIVATE_KEY)

DECLARE_ASN1_FUNCTIONS(RSA_PUBLIC_KEY);
ASN1_SEQUENCE(RSA_PUBLIC_KEY) = {
	ASN1_SIMPLE(RSA_PUBLIC_KEY, n, ASN1_INTEGER),
	ASN1_SIMPLE(RSA_PUBLIC_KEY, e, ASN1_INTEGER),
} ASN1_SEQUENCE_END(RSA_PUBLIC_KEY)
IMPLEMENT_ASN1_FUNCTIONS(RSA_PUBLIC_KEY)

void print(const ASN1_INTEGER* str, const char* item)
{
	fprintf(stdout, "name: %s, type: %d, length: %d, data: ", item, str->type, str->length);
	for (int i = 0; i < str->length; ++i) {
		fprintf(stdout, "%02X", str->data[i]);
	}
	fprintf(stdout, "\n");
}

} // namespace

int test_openssl_base64();
int openssl_base64_encode(const unsigned char* in, int inlen, char* out, int* outlen, bool newline = true);
int openssl_base64_decode(const char* in, int inlen, unsigned char* out, int* outlen, bool newline = true);
int test_openssl_parse_rsa_pem();
int test_openssl_asn1();
int test_openssl_aes_gcm();
int test_openssl_des();
int test_openssl_rc4();
int test_openssl_md5();
int test_openssl_rsa();
int test_openssl_aes();
int test_openssl_hmac();

#endif // FBC_OPENSSL_TEST_FUNSET_HPP_

