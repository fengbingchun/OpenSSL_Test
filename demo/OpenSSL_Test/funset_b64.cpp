#include "funset.hpp"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string>
#include <b64/b64.h>

// Blog: https://blog.csdn.net/fengbingchun/article/details/85218653

namespace {
// reference: https://stackoverflow.com/questions/342409/how-do-i-base64-encode-decode-in-c
static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
				'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
				'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
				'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
				'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
				'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
				'w', 'x', 'y', 'z', '0', '1', '2', '3',
				'4', '5', '6', '7', '8', '9', '+', '/' };
static char *decoding_table = NULL;
static int mod_table[] = { 0, 2, 1 };

void build_decoding_table()
{
	decoding_table = (char*)malloc(256);

	for (int i = 0; i < 64; i++)
		decoding_table[(unsigned char)encoding_table[i]] = i;
}

char* base64_encode(const unsigned char *data, size_t input_length, size_t *output_length)
{
	*output_length = 4 * ((input_length + 2) / 3);

	char *encoded_data = (char*)malloc(*output_length);
	if (encoded_data == NULL) return NULL;

	for (int i = 0, j = 0; i < input_length;) {
		uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
		uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
		uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;

		uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

		encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
		encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
		encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
		encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
	}

	for (int i = 0; i < mod_table[input_length % 3]; i++)
		encoded_data[*output_length - 1 - i] = '=';

	return encoded_data;
}

unsigned char* base64_decode(const char *data, size_t input_length, size_t *output_length)
{
	if (decoding_table == NULL) build_decoding_table();

	if (input_length % 4 != 0) return NULL;

	*output_length = input_length / 4 * 3;
	if (data[input_length - 1] == '=') (*output_length)--;
	if (data[input_length - 2] == '=') (*output_length)--;

	unsigned char *decoded_data = (unsigned char*)malloc(*output_length);
	if (decoded_data == NULL) return NULL;

	for (int i = 0, j = 0; i < input_length;) {
		uint32_t sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
		uint32_t sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
		uint32_t sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
		uint32_t sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];

		uint32_t triple = (sextet_a << 3 * 6)
			+ (sextet_b << 2 * 6)
			+ (sextet_c << 1 * 6)
			+ (sextet_d << 0 * 6);

		if (j < *output_length) decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
		if (j < *output_length) decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
		if (j < *output_length) decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
	}

	return decoded_data;
}

void base64_cleanup()
{
	free(decoding_table);
}

} // namespace

int test_b64_base64()
{
	std::string str = "北京ABC123+-*/&@!?0";
	fprintf(stdout, "str source : %s\n", str.c_str());

	char* str_en = b64_encode((const unsigned char*)str.c_str(), str.length());
	fprintf(stdout, "str encode : %s\n", str_en);

	std::string tmp(str_en);
	//fprintf(stdout, "str_en length: %d\n", tmp.length());
	unsigned char* str_de = b64_decode(tmp.c_str(), tmp.length());
	fprintf(stdout, "str decode : %s\n", str_de);

	free(str_en);
	free(str_de);

	size_t output_length_encode = 0;
	char* str_en2 = base64_encode((const unsigned char*)str.c_str(), str.length(), &output_length_encode);
	std::string tmp2(str_en2, output_length_encode);
	fprintf(stdout, "str encode2: %s\n", tmp2.c_str());

	size_t output_length_decode = 0;
	//fprintf(stdout, "output_length_encode: %d, str_en2 length: %d\n", output_length_encode, tmp2.length());
	unsigned char* str_de2 = base64_decode(str_en2, output_length_encode, &output_length_decode);
	std::string tmp3((char*)str_de2, output_length_decode);
	fprintf(stdout, "str decode2: %s\n", tmp3.c_str());

	free(str_en2);
	free(str_de2);
	base64_cleanup();

	return 0;
}
