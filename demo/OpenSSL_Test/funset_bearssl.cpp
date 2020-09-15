#include "funset.hpp"
#include <string.h>
#include <string>
#include <vector>
#include <memory>
#include <iostream>
#include <algorithm>
#include <system_error>

#ifdef __linux__
#include <sys/select.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#endif

#include "bearssl_hash.h"
#include "bearssl_block.h"
#include "bearssl_hmac.h"
#include "bearssl_ssl.h"
#include "base64url.h"

#include "trust_anchors.inc"
#include "key.inc"
#include "chain.inc"

//////////////////////////////// self signed certificate ///////////////////////////
// Blog: https://blog.csdn.net/fengbingchun/article/details/108593942
namespace {

// reference: bearssl/samples: client_basic.c/server_basic.c
// 客户端连接服务器：host为服务器端ipv4或域名，port为端口号
SOCKET client_connect(const char *host, const char *port)
{
	struct addrinfo hints, *si;
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	// getaddrinfo: 获取主机信息，既支持ipv4也支持ipv6
	auto err = getaddrinfo(host, port, &hints, &si);
	if (err != 0) {
		fprintf(stderr, "fail to getaddrinfo: %s\n", gai_strerror(err));
		return INVALID_SOCKET;
	}

	SOCKET fd = INVALID_SOCKET;
	struct addrinfo* p = nullptr;
	for (p = si; p != nullptr; p = p->ai_next) {
		struct sockaddr* sa = (struct sockaddr *)p->ai_addr;
		if (sa->sa_family != AF_INET) // 仅处理AF_INET
			continue;

		struct in_addr addr;
		addr.s_addr = ((struct sockaddr_in *)(p->ai_addr))->sin_addr.s_addr;
		// inet_ntoa: 将二进制类型的IP地址转换为字符串类型
		fprintf(stdout, "server ip: %s, family: %d, socktype: %d, protocol: %d\n",
			inet_ntoa(addr), p->ai_family, p->ai_socktype, p->ai_protocol);

		// 创建流式套接字
		fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		if (fd < 0 || fd == INVALID_SOCKET) {
			auto err_code = get_error_code();
			std::error_code ec(err_code, std::system_category());
			fprintf(stderr, "fail to socket: %d, error code: %d, message: %s\n", fd, err_code, ec.message().c_str());
			continue;
		}

		// 连接，connect函数的第二参数是一个指向数据结构sockaddr的指针，其中包括客户端需要连接的服务器的目的端口和IP地址，以及协议类型
#ifdef __linux__
		auto ret = connect(fd, p->ai_addr, p->ai_addrlen); // 在windows上直接调用此语句会返回-1，还未查到原因?
#else
		struct sockaddr_in server_addr;
		memset(&server_addr, 0, sizeof(server_addr));
		server_addr.sin_family = AF_INET;
		server_addr.sin_port = htons(server_port_);
		auto ret = inet_pton(AF_INET, server_ip_, &server_addr.sin_addr);
		if (ret != 1) {
			fprintf(stderr, "fail to inet_pton: %d\n", ret);
			return -1;
		}
		ret = connect(fd, (struct sockaddr*)&server_addr, sizeof(server_addr));
#endif
		if ( ret < 0) {
			auto err_code = get_error_code();
			std::error_code ec(err_code, std::system_category());
			fprintf(stderr, "fail to connect: %d, error code: %d, message: %s\n", ret, err_code, ec.message().c_str());
			close(fd);
			continue;
		}

		break;
	}

	if (p == nullptr) {
		freeaddrinfo(si);
		fprintf(stderr, "fail to socket or connect\n");
		return INVALID_SOCKET;
	}

	freeaddrinfo(si);
	return fd;
}

// 接收数据
int sock_read(void *ctx, unsigned char *buf, size_t len)
{
	for (;;) {
#ifdef _MSC_VER
		auto rlen = recv(*(int*)ctx, (char*)buf, len, 0);
#else
		auto rlen = recv(*(int*)ctx, (char*)buf, len, 0);
#endif
		//fprintf(stderr, "recv length: %d\n", rlen);
		if (rlen <= 0) {
			if (rlen < 0 && errno == EINTR) {
				continue;
			}

			auto err_code = get_error_code();
			std::error_code ec(err_code, std::system_category());
			fprintf(stderr, "fail to recv: %d, err code: %d, message: %s\n", rlen, err_code, ec.message().c_str());
			return -1;
		}
		return (int)rlen;
	}
}

// 发送数据
int sock_write(void *ctx, const unsigned char *buf, size_t len)
{
	for (;;) {
#ifdef _MSC_VER
		auto wlen = send(*(int *)ctx, (const char*)buf, len, 0);
#else
		// MSG_NOSIGNAL: 禁止send函数向系统发送异常消息
		auto wlen = send(*(int *)ctx, buf, len, MSG_NOSIGNAL);
#endif
		//fprintf(stderr, "send length: %d\n", wlen);
		if (wlen <= 0) {
			if (wlen < 0 && errno == EINTR) {
				continue;
			}

			auto err_code = get_error_code();
			std::error_code ec(err_code, std::system_category());
			fprintf(stderr, "fail to send: %d, err code: %d, message: %s\n", wlen, err_code, ec.message().c_str());
			return -1;
		}
		return (int)wlen;
	}
}

// 服务器端绑定、监听
SOCKET server_bind_listen(const char *host, const char *port)
{
	struct addrinfo hints, *si;
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	auto ret = getaddrinfo(host, port, &hints, &si);
	if (ret != 0) {
		fprintf(stderr, "fail to getaddrinfo: %s\n", gai_strerror(ret));
		return INVALID_SOCKET;
	}

	SOCKET fd = INVALID_SOCKET;
	struct addrinfo* p = nullptr;
	for (p = si; p != nullptr; p = p->ai_next) {
		struct sockaddr *sa = (struct sockaddr *)p->ai_addr;
		if (sa->sa_family != AF_INET) // 仅处理AF_INET
			continue;

		struct in_addr addr;
		addr.s_addr = ((struct sockaddr_in *)(p->ai_addr))->sin_addr.s_addr;
		// inet_ntoa: 将二进制类型的IP地址转换为字符串类型
		fprintf(stdout, "server ip: %s, family: %d, socktype: %d, protocol: %d\n",
			inet_ntoa(addr), p->ai_family, p->ai_socktype, p->ai_protocol);

		// 创建流式套接字
		fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		if (fd < 0 || fd == INVALID_SOCKET) {
			auto err_code = get_error_code();
			std::error_code ec(err_code, std::system_category());
			fprintf(stderr, "fail to socket: %d, error code: %d, message: %s\n", fd, err_code, ec.message().c_str());
			continue;
		}

		int opt = 1;
#ifdef _MSC_VER
		ret = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof opt);
#else
		ret = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof opt);
#endif
		if (ret < 0) {
			fprintf(stderr, "fail to setsockopt: send\n");
			return INVALID_SOCKET;
		}

		// 绑定地址端口
		ret = bind(fd, sa, sizeof(*sa));
		if (ret < 0) {
			auto err_code = get_error_code();
			std::error_code ec(err_code, std::system_category());
			fprintf(stderr, "fail to bind: %d, error code: %d, message: %s\n", ret, err_code, ec.message().c_str());
			close(fd);
			continue;
		}

		break;
	}

	if (p == nullptr) {
		freeaddrinfo(si);
		fprintf(stderr, "fail to socket or bind\n");
		return INVALID_SOCKET;
	}

	freeaddrinfo(si);

	ret = listen(fd, server_listen_queue_length_);
	if (ret < 0) {
		auto err_code = get_error_code();
		std::error_code ec(err_code, std::system_category());
		fprintf(stderr, "fail to listen: %d, error code: %d, message: %s\n", ret, err_code, ec.message().c_str());
		close(fd);
		return INVALID_SOCKET;
	}

	return fd;
}

// 服务器端接收客户端的连接
SOCKET server_accept(SOCKET server_fd)
{
	struct sockaddr_in sa;
	socklen_t sa_len = sizeof sa;
	auto fd = accept(server_fd, (struct sockaddr*)&sa, &sa_len);
	if (fd < 0) {
		auto err_code = get_error_code();
		std::error_code ec(err_code, std::system_category());
		fprintf(stderr, "fail to accept: %d, error code: %d, message: %s\n", fd, err_code, ec.message().c_str());
		return -1;
	}

	if (sa.sin_family != AF_INET) {
		fprintf(stderr, "fail: sa_family should be equal AF_INET: %d\n", sa.sin_family);
		return -1;
	}

	struct in_addr addr;
	addr.s_addr = sa.sin_addr.s_addr;
	// inet_ntoa: 将二进制类型的IP地址转换为字符串类型
	fprintf(stdout, "client ip: %s\n", inet_ntoa(addr));
	return fd;
}

// Check whether we closed properly or not
void check_ssl_error(const br_ssl_client_context& sc)
{
	if (br_ssl_engine_current_state(&sc.eng) == BR_SSL_CLOSED) {
		auto ret = br_ssl_engine_last_error(&sc.eng);
		if (ret == 0) {
			fprintf(stdout, "closed properly\n");
		} else {
			fprintf(stderr, "SSL error %d\n", ret);
		}
	} else {
		fprintf(stderr, "socket closed without proper SSL termination\n");
	}
}

void check_ssl_error(const br_ssl_server_context& ss)
{
	if (br_ssl_engine_current_state(&ss.eng) == BR_SSL_CLOSED) {
		auto ret = br_ssl_engine_last_error(&ss.eng);
		if (ret == 0) {
			fprintf(stdout, "closed properly\n");
		} else {
			fprintf(stderr, "SSL error %d\n", ret);
		}
	} else {
		fprintf(stderr, "socket closed without proper SSL termination\n");
	}
}

// reference: bearssl/samples/custom_profile.c
void set_ssl_engine_suites(br_ssl_client_context sc)
{
	static const uint16_t suites[] = {
		BR_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		BR_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		BR_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		BR_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		BR_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		BR_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		BR_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
		BR_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		BR_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
		BR_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
		BR_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		BR_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		BR_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		BR_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		BR_TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
		BR_TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,
		BR_TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,
		BR_TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384,
		BR_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,
		BR_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,
		BR_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384,
		BR_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,
		BR_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,
		BR_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,
		BR_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA,
		BR_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,
		BR_TLS_RSA_WITH_AES_128_GCM_SHA256,
		BR_TLS_RSA_WITH_AES_256_GCM_SHA384,
		BR_TLS_RSA_WITH_AES_128_CBC_SHA256,
		BR_TLS_RSA_WITH_AES_256_CBC_SHA256,
		BR_TLS_RSA_WITH_AES_128_CBC_SHA,
		BR_TLS_RSA_WITH_AES_256_CBC_SHA,
		BR_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
		BR_TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		BR_TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA,
		BR_TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA,
		BR_TLS_RSA_WITH_3DES_EDE_CBC_SHA
	};

	br_ssl_engine_set_suites(&sc.eng, suites, (sizeof suites) / (sizeof suites[0]));
}

} // namespace

int test_bearssl_self_signed_certificate_client()
{
#ifdef _MSC_VER
	init_server_trust_anchors();
#endif

	const char* host = server_ip_;
	const char* port = std::to_string(server_port_).c_str();

	// Open the socket to the target server
	SOCKET fd = client_connect(host, port);
	if (fd < 0 || fd == INVALID_SOCKET) {
		fprintf(stderr, "fail to client connect: %d\n", fd);
		return -1;
	}

	// Initialise the client context
	br_ssl_client_context sc;
	br_x509_minimal_context xc;
	br_ssl_client_init_full(&sc, &xc, SERVER_TAs, SERVER_TAs_NUM);

	set_ssl_engine_suites(sc);

	// 以下单条语句用于双向认证中
	br_ssl_client_set_single_rsa(&sc, CLIENT_CHAIN, CLIENT_CHAIN_LEN, &CLIENT_RSA, br_rsa_pkcs1_sign_get_default());

	// Set the I/O buffer to the provided array
	unsigned char iobuf[BR_SSL_BUFSIZE_BIDI];
	br_ssl_engine_set_buffer(&sc.eng, iobuf, sizeof iobuf, 1);

	// Reset the client context, for a new handshake
	// 若设置br_ssl_client_reset函数的第二个参数为nullptr，则客户端无需验证服务器端的ip或域名,
	// 若第二个参数不为nullptr，则这里的host与使用命令生成server.csr时的CN要保持一致
	auto ret = br_ssl_client_reset(&sc, host/*nullptr*/, 0);
	if ( ret == 0) {
		check_ssl_error(sc);
		fprintf(stderr, "fail to br_ssl_client_reset: %d\n", ret);
		return -1;
	}

	// Initialise the simplified I/O wrapper context
	br_sslio_context ioc;
	br_sslio_init(&ioc, &sc.eng, sock_read, &fd, sock_write, &fd);

	// Write application data unto a SSL connection
	const char* source_buffer = "https://blog.csdn.net/fengbingchun";
	auto length = strlen(source_buffer) + 1; // 以空字符作为发送结束的标志
	ret = br_sslio_write_all(&ioc, source_buffer, length);
	if (ret < 0) {
		check_ssl_error(sc);
		fprintf(stderr, "fail to br_sslio_write_all: %d\n", ret);
		return -1;
	}

	// SSL is a buffered protocol: we make sure that all our request bytes are sent onto the wire
	ret = br_sslio_flush(&ioc);
	if (ret < 0) {
		check_ssl_error(sc);
		fprintf(stderr, "fail to br_sslio_flush: %d\n", ret);
		return -1;
	}

	// Read the server's response
	std::vector<char> vec;
	for (;;) {
		unsigned char tmp[512];
		ret = br_sslio_read(&ioc, tmp, sizeof tmp);
		if (ret < 0) {
			check_ssl_error(sc);
			fprintf(stderr, "fail to br_sslio_read: %d\n", ret);
			return -1;
		}

		bool flag = false;
		std::for_each(tmp, tmp + ret, [&flag, &vec](const char& c) {
			if (c == '\0') flag = true; // 以空字符作为接收结束的标志
			else vec.emplace_back(c);
		});

		if (flag == true) break;
	}

	fprintf(stdout, "server's response: ");
	std::for_each(vec.data(), vec.data() + vec.size(), [](const char& c){
		fprintf(stdout, "%c", c);
	});
	fprintf(stdout, "\n");

	// Close the SSL connection
	if (fd >= 0) {
		ret = br_sslio_close(&ioc);
		if (ret < 0) {
			check_ssl_error(sc);
			fprintf(stderr, "fail to br_sslio_close: %d\n", ret);
			return -1;
		}
	}

	// Close the socket
	close(fd);

	return 0;
}

int test_bearssl_self_signed_certificate_server()
{
#ifdef _MSC_VER
	init_client_trust_anchors();
#endif

	// Open the server socket
	SOCKET fd = server_bind_listen(server_ip_, std::to_string(server_port_).c_str());
	if (fd < 0 || fd == INVALID_SOCKET) {
		fprintf(stderr, "fail to server_bind_listen: %d\n", fd);
		return -1;
	}

	// Process each client, one at a time
	for (;;) {
		SOCKET fd2 = server_accept(fd);
		if (fd2 < 0 || fd2 == INVALID_SOCKET) {
			fprintf(stderr, "fail to server_accept: %d\n", fd2);
			return -1;
		}

		// Initialise the context with the cipher suites and algorithms
		// SSL server profile: full_rsa
		br_ssl_server_context sc;
		br_ssl_server_init_full_rsa(&sc, SERVER_CHAIN, SERVER_CHAIN_LEN, &SERVER_RSA);

		// 以下8条语句用于双向认证中
		br_x509_minimal_context xc;
		br_x509_minimal_init(&xc, &br_sha1_vtable, CLIENT_TAs, CLIENT_TAs_NUM);
		br_ssl_engine_set_default_rsavrfy(&sc.eng);
		br_ssl_engine_set_default_ecdsa(&sc.eng);
		br_x509_minimal_set_rsa(&xc, br_rsa_pkcs1_vrfy_get_default());
		br_x509_minimal_set_ecdsa(&xc, br_ec_get_default(), br_ecdsa_vrfy_asn1_get_default());
		br_ssl_engine_set_x509(&sc.eng, &xc.vtable);
		br_ssl_server_set_trust_anchor_names_alt(&sc, CLIENT_TAs, CLIENT_TAs_NUM);

		// Set the I/O buffer to the provided array
		unsigned char iobuf[BR_SSL_BUFSIZE_BIDI];
		br_ssl_engine_set_buffer(&sc.eng, iobuf, sizeof iobuf, 1);

		// Reset the server context, for a new handshake
		auto ret = br_ssl_server_reset(&sc);
		if (ret == 0) {
			check_ssl_error(sc);
			fprintf(stderr, "fail to br_ssl_server_reset: %d\n", ret);
			return -1;
		}

		// Initialise the simplified I/O wrapper context
		br_sslio_context ioc;
		br_sslio_init(&ioc, &sc.eng, sock_read, &fd2, sock_write, &fd2);

		std::vector<char> vec;
		for (;;) {
			unsigned char tmp[512];
			ret = br_sslio_read(&ioc, tmp, sizeof tmp);
			if (ret < 0) {
				check_ssl_error(sc);
				fprintf(stderr, "fail to br_sslio_read: %d\n", ret);
				return -1;
			}

			bool flag = false;
			std::for_each(tmp, tmp + ret, [&flag, &vec](const char& c) {
				if (c == '\0') flag = true; // 以空字符作为接收结束的标志
				else vec.emplace_back(c);
			});

			if (flag == true) break;
		}

		fprintf(stdout, "message from the client: ");
		std::for_each(vec.data(), vec.data() + vec.size(), [](const char& c){
			fprintf(stdout, "%c", c);
		});
		fprintf(stdout, "\n");

		// Write a response and close the connection
		auto str = std::to_string(vec.size());
		std::vector<char> vec2(str.size() + 1);
		memcpy(vec2.data(), str.data(), str.size());
		vec2[str.size()] = '\0'; // 以空字符作为发送结束的标志
		ret = br_sslio_write_all(&ioc, vec2.data(), vec2.size());
		if (ret < 0) {
			check_ssl_error(sc);
			fprintf(stderr, "fail to br_sslio_write_all: %d\n", ret);
			return -1;
		}
		ret = br_sslio_close(&ioc);
		if (ret < 0) {
			check_ssl_error(sc);
			fprintf(stderr, "fail to br_sslio_close: %d\n", ret);
			return -1;
		}

		close(fd2);
	}

	return 0;
}

////////////////////////// hmac-sha256, JWT(JSON WEB Token) ////////////////////
// Blog: https://blog.csdn.net/fengbingchun/article/details/106786010
int test_bearssl_hs256()
{
	// encode header
	const char* header = "{\"alg\":\"HS256\",\"typ\":\"JWT\",\"id\":\"fengbingchun\"}";
	int length_header = strlen(header);
	int length_encoded_header = (length_header + 2) / 3 * 4;
	std::unique_ptr<char[]> encoded_header(new char[length_encoded_header]);
	int ret = base64url_encode((const unsigned char*)header, length_header, encoded_header.get());
	if (ret != BASE64_OK) {
		fprintf(stderr, "fail to encode header: %s\n", header);
		return -1;
	}
	fprintf(stdout, "encoded header: %s\n", encoded_header.get());

	// encode payload
	const char* payload = "{\"csdn\":\"https://blog.csdn.net/fengbingchun\",\"github\":\"https://github.com//fengbingchun\"}";
	int length_payload = strlen(payload);
	int length_encoded_payload = (length_payload + 2) / 3 * 4;
	std::unique_ptr<char[]> encoded_payload(new char[length_encoded_payload]);
	ret = base64url_encode((const unsigned char*)payload, length_payload, encoded_payload.get());
	if (ret != BASE64_OK) {
		fprintf(stderr, "fail to encode payload: %s\n", payload);
		return -1;
	}
	fprintf(stdout, "encoded payload: %s\n", encoded_payload.get());

	// signature
	std::string buffer;
	buffer.append(encoded_header.get(), strlen(encoded_header.get()));
	buffer.append(".");
	buffer.append(encoded_payload.get(), strlen(encoded_payload.get()));

	//const unsigned char key[] = { // 32 bytes
	//	0xee, 0xbc, 0x1f, 0x57, 0x48, 0x7f, 0x51, 0x92, 0x1c, 0x04, 0x65, 0x66,
	//	0x5f, 0x8a, 0xe6, 0xd1, 0x65, 0x8b, 0xb2, 0x6d, 0xe6, 0xf8, 0xa0, 0x69,
	//	0xa3, 0x52, 0x02, 0x93, 0xa5, 0x72, 0x07, 0x8f };
	const char key[] = { // 32 bytes
		'1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '+', '-',
		'!', '@', '#', '$', '%', '^', '&', '*', 'x', '(', ')', '_',
		'=', 'Q', 'F', '{', '>', '<', '/', '?' };

	br_hmac_key_context key_ctx;
	br_hmac_context ctx;
	br_hmac_key_init(&key_ctx, &br_sha256_vtable, key, sizeof(key));
	br_hmac_init(&ctx, &key_ctx, 0);
	size_t length_signature = br_hmac_size(&ctx);

	br_hmac_update(&ctx, buffer.c_str(), buffer.length());
	std::unique_ptr<unsigned char[]> signature(new unsigned char[length_signature]);
	size_t length_signature2 = br_hmac_out(&ctx, signature.get());

	// encode signature
	int length_encoded_signature = (length_signature + 2) / 3 * 4;
	std::unique_ptr<char[]> encoded_signature(new char[length_encoded_signature]);
	ret = base64url_encode(signature.get(), length_signature, encoded_signature.get());
	if (ret != BASE64_OK) {
		fprintf(stderr, "fail to encode signature\n");
		return -1;
	}
	fprintf(stdout, "encoded signature: %s\n", encoded_signature.get());

	buffer.append(".");
	buffer.append(encoded_signature.get(), strlen(encoded_signature.get()));
	fprintf(stdout, "jwt result: %s\n", buffer.c_str());

	return 0;
}

///////////////////////////////////////////////////////////
// Blog: https://blog.csdn.net/fengbingchun/article/details/104876336
namespace {

void print(const char* name, const unsigned char* data, unsigned int len)
{
	fprintf(stdout, "%s:", name);
	for (unsigned i = 0; i < len; ++i) {
		fprintf(stdout, "%02X", data[i]);
	}
	fprintf(stdout, "\n");
}

}

int test_bearssl_1()
{
	// compute a hash function
	const std::string data1 = "https://blog.csdn.net/fengbingchun";
	unsigned char hash_output_sha256[br_sha256_SIZE] = { 0 };
	br_sha256_context csha256;
	br_sha256_init(&csha256);
	br_sha256_update(&csha256, data1.c_str(), data1.length());
	br_sha256_out(&csha256, hash_output_sha256);
	print("sha256", hash_output_sha256, br_sha256_SIZE);

	const std::string data2 = "https://github.com/fengbingchun";
	unsigned char hash_output_sha1[br_sha1_SIZE] = { 0 };
	br_sha1_context csha1;
	br_sha1_init(&csha1);
	br_sha1_update(&csha1, data2.c_str(), data2.length());
	br_sha1_out(&csha1, hash_output_sha1);
	print("sha1", hash_output_sha1, br_sha1_SIZE);

	// aes cbc encryption/decryption
	static const char* const key = "012346789abcdef";
	static const char* const iv_src = "ABCDEF9876543210";
	char* data3_src = "!@#$%^&*()_-+={]";

	br_aes_big_cbcenc_keys cbcenc_ctx;
	br_aes_big_cbcenc_init(&cbcenc_ctx, key, br_aes_big_BLOCK_SIZE);
	std::vector<unsigned char> iv(br_aes_big_BLOCK_SIZE, 0);
	memcpy(iv.data(), iv_src, br_aes_big_BLOCK_SIZE);
	if (strlen(data3_src) % br_aes_big_BLOCK_SIZE != 0) {
		fprintf(stdout, "data length (in bytes, MUST be multiple of 16): %d\n", strlen(data3_src));
		return -1;
	}
	std::vector<unsigned char> data3(br_aes_big_BLOCK_SIZE, 0);
	memcpy(data3.data(), data3_src, br_aes_big_BLOCK_SIZE);
	print("data3 src", data3.data(), br_aes_big_BLOCK_SIZE);
	br_aes_big_cbcenc_run(&cbcenc_ctx, iv.data(), data3.data(), br_aes_big_BLOCK_SIZE);
	print("data3 enc", data3.data(), br_aes_big_BLOCK_SIZE);

	br_aes_big_cbcdec_keys cbcdec_ctx;
	br_aes_big_cbcdec_init(&cbcdec_ctx, key, br_aes_big_BLOCK_SIZE);
	std::vector<unsigned char> iv2(br_aes_big_BLOCK_SIZE, 0);
	memcpy(iv2.data(), iv_src, br_aes_big_BLOCK_SIZE);
	br_aes_big_cbcdec_run(&cbcdec_ctx, iv2.data(), data3.data(), br_aes_big_BLOCK_SIZE);
	print("data3 dec", data3.data(), br_aes_big_BLOCK_SIZE);
	fprintf(stdout, "data3 src:          : %s\n", data3_src);
	fprintf(stdout, "data3 decrypt result: %s\n", data3.data());

	return 0;
}

