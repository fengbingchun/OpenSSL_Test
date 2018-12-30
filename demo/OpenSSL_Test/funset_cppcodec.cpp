#include "funset.hpp"
#include <iostream>
#include <string>
#include <vector>
#ifdef __linux__
#include <cppcodec/base64_rfc4648.hpp>
#endif

int test_cppcodec_base64_rfc4648()
{
	std::string str = "北京ABC123+-*/&@!?0";
	fprintf(stdout, "str   : %s\n", str.c_str());
#ifdef __linux__
	using base64 = cppcodec::base64_rfc4648;
	std::string str_en = base64::encode(str.c_str(), str.length());
	fprintf(stdout, "str_en: %s\n", str_en.c_str());
	std::vector<uint8_t> str_de = base64::decode(str_en.c_str(), str_en.length());
	fprintf(stdout, "str_de: %s\n", str_de.data());
	
#else
	fprintf(stderr, "Error: build cppcodec need to vs2015 or vs2017 in windows\n");
	return -1;
#endif
}
