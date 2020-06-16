#include "funset.hpp"
#include <string.h>
#include <string>
#include <vector>
#include <memory>
#include "bearssl_hash.h"
#include "bearssl_block.h"
#include "bearssl_hmac.h"
#include "base64url.h"

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

