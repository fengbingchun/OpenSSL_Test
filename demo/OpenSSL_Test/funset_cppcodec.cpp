#include "funset.hpp"
#include <iostream>
#ifdef __linux__
#include <cppcodec/base64_rfc4648.hpp>
#endif

int test_ccpcodec_base64_rfc4648()
{
#ifdef __linux__
	return -1;
#else
	fprintf(stderr, "Error: build cppcodec need to vs2015 or vs2017 in windows\n");
	return -1;
#endif
}
