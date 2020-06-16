#include "funset.hpp"
#include <string.h>
#include <memory>
#include "base64url.h"

int test_base64url()
{
	const char* url = "https://blog.csdn.net/fengbingchun";
	int length_src = strlen(url);
	int length_encoded = (length_src + 2) / 3 * 4;
	std::unique_ptr<char[]> encoded(new char[length_encoded]);
	int ret = base64url_encode((const unsigned char*)url, length_src, encoded.get());
	if (ret != BASE64_OK) {
		fprintf(stderr, "fail to encode: %s\n", url);
		return -1;
	}
	fprintf(stdout, "encoded: %s\n", encoded.get());

	std::unique_ptr<unsigned char[]> decoded(new unsigned char[length_encoded]);
	memset(decoded.get(), 0, length_encoded);

	ret = base64url_decode(encoded.get(), strlen(encoded.get()), decoded.get());
	if (ret != BASE64_OK) {
		fprintf(stderr, "fail to decode: %s\n", encoded.get());
		return -1;
	}
	fprintf(stdout, "decoded: %s\n", decoded.get());

	if (strcmp(url, (const char*)decoded.get()) != 0) {
		fprintf(stderr, "fail to encode or decode: %s\n", url);
		return -1;
	}

	return 0;
}
