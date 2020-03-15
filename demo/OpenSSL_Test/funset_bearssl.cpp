#include "funset.hpp"
#include <string.h>
#include <string>
#include <vector>
#include "bearssl_hash.h"
#include "bearssl_block.h"

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

