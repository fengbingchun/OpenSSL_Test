#ifndef FBC_OPENSSL_TEST_FUNSET_HPP_
#define FBC_OPENSSL_TEST_FUNSET_HPP_

#ifdef _MSC_VER
#include <WinSock2.h>
#include <winsock.h>
#include <ws2tcpip.h>
#else
#include <errno.h>
#ifndef INVALID_SOCKET
#define INVALID_SOCKET (-1)
#endif
#endif

#include <openssl/asn1.h>
#include <openssl/asn1t.h>

int test_jwt(); // JSON WEB Token

// base64url
int test_base64url();

// bearssl
int test_bearssl_1();
int test_bearssl_hs256(); // hmac sha256
int test_bearssl_self_signed_certificate_client(); // 自签名证书双向认证,客户端
int test_bearssl_self_signed_certificate_server(); // 自签名证书双向认证，服务器端

// socket
int test_select_1();
int test_get_hostname_ip();
int test_socket_tcp_client();
int test_socket_tcp_server();

// test libcurl interface
int test_curl_proxy_http();
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

const char* server_ip_ = "10.4.96.33"; // 服务器ip
const int server_port_ = 9999; // 服务器端口号,需确保此端口未被占用
			       // linux: $ netstat -nap | grep 6666; kill -9 PID
			       // windows: tasklist | findstr OpenSSL_Test.exe; taskkill /T /F /PID PID
const int server_listen_queue_length_ = 100; // 服务器listen队列支持的最大长度

#ifdef _MSC_VER
// 每一个WinSock应用程序必须在开始操作前初始化WinSock的动态链接库(DLL)，并在操作完成后通知DLL进行清除操作
class WinSockInit {
public:
	WinSockInit()
	{
		WSADATA wsaData;
		// WinSock应用程序在开始时必须要调用WSAStartup函数，结束时调用WSACleanup函数
		// WSAStartup函数必须是WinSock应用程序调用的第一个WinSock函数，否则，其它的WinSock API函数都将会失败并返回错误值
		int ret = WSAStartup(MAKEWORD(2, 2), &wsaData);
		if (ret != NO_ERROR)
			fprintf(stderr, "fail to init winsock: %d\n", ret);
	}

	~WinSockInit()
	{
		WSACleanup();
	}
};

static WinSockInit win_sock_init_;

#define close(fd) closesocket(fd)
#define socklen_t int
#else
#define SOCKET int
#endif

int get_error_code()
{
#ifdef _MSC_VER
	auto err_code = WSAGetLastError();
#else
	auto err_code = errno;
#endif
	return err_code;
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

