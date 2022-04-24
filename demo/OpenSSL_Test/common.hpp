#ifndef FBC_OPENSSL_TEST_COMMON_HPP_
#define FBC_OPENSSL_TEST_COMMON_HPP_

#define CHECK(x) { \
	if (x) {} \
	else { fprintf(stderr, "Check Failed: %s, file: %s, line: %d\n", #x, __FILE__, __LINE__); exit(1); } \
}

#endif // FBC_OPENSSL_TEST_COMMON_HPP_
