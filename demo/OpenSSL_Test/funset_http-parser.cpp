#include "funset.hpp"
#include <string.h>
#include <assert.h>
#include <iostream>
#include <http-parser/http_parser.h>

// Blog: https://blog.csdn.net/fengbingchun/article/details/85224885

namespace {

#define MAX_HEADERS 13
#define MAX_ELEMENT_SIZE 2048
#define MAX_CHUNKS 16

struct message {
	const char *name; // for debugging purposes
	const char *raw;
	enum http_parser_type type;
	enum http_method method;
	int status_code;
	char response_status[MAX_ELEMENT_SIZE];
	char request_path[MAX_ELEMENT_SIZE];
	char request_url[MAX_ELEMENT_SIZE];
	char fragment[MAX_ELEMENT_SIZE];
	char query_string[MAX_ELEMENT_SIZE];
	char body[MAX_ELEMENT_SIZE];
	size_t body_size;
	const char *host;
	const char *userinfo;
	uint16_t port;
	int num_headers;
	enum { NONE = 0, FIELD, VALUE } last_header_element;
	char headers[MAX_HEADERS][2][MAX_ELEMENT_SIZE];
	int should_keep_alive;

	int num_chunks;
	int num_chunks_complete;
	int chunk_lengths[MAX_CHUNKS];

	const char *upgrade; // upgraded body

	unsigned short http_major;
	unsigned short http_minor;

	int message_begin_cb_called;
	int headers_complete_cb_called;
	int message_complete_cb_called;
	int status_cb_called;
	int message_complete_on_eof;
	int body_is_final;
};

int num_messages = 0;
http_parser* parser = nullptr;
struct message messages[5];
int currently_parsing_eof = 0;

int message_begin_cb(http_parser* p)
{
	assert(p == parser);
	messages[num_messages].message_begin_cb_called = true;
	return 0;
}

size_t strnlen(const char* s, size_t maxlen)
{
	const char* p = (const char*)memchr(s, '\0', maxlen);
	if (p == NULL)
		return maxlen;

	return p - s;
}

size_t strlncat(char* dst, size_t len, const char* src, size_t n)
{
	size_t slen = strnlen(src, n);
	size_t dlen = strnlen(dst, len);

	if (dlen < len) {
		size_t rlen = len - dlen;
		size_t ncpy = slen < rlen ? slen : (rlen - 1);
		memcpy(dst + dlen, src, ncpy);
		dst[dlen + ncpy] = '\0';
	}

	assert(len > slen + dlen);
	return slen + dlen;
}

int header_field_cb(http_parser* p, const char* buf, size_t len)
{
	assert(p == parser);
	struct message *m = &messages[num_messages];

	if (m->last_header_element != m->FIELD)
		m->num_headers++;

	strlncat(m->headers[m->num_headers - 1][0], sizeof(m->headers[m->num_headers - 1][0]), buf, len);
	m->last_header_element = m->FIELD;
	return 0;
}

int header_value_cb(http_parser* p, const char* buf, size_t len)
{
	assert(p == parser);
	message *m = &messages[num_messages];

	strlncat(m->headers[m->num_headers - 1][1], sizeof(m->headers[m->num_headers - 1][1]), buf, len);
	m->last_header_element = m->VALUE;
	return 0;
}

int request_url_cb(http_parser* p, const char* buf, size_t len)
{
	assert(p == parser);
	strlncat(messages[num_messages].request_url, sizeof(messages[num_messages].request_url), buf, len);
	return 0;
}

int response_status_cb(http_parser*p, const char* buf, size_t len)
{
	assert(p == parser);
	messages[num_messages].status_cb_called = true;

	strlncat(messages[num_messages].response_status, sizeof(messages[num_messages].response_status), buf, len);
	return 0;
}

void check_body_is_final(const http_parser* p)
{
	if (messages[num_messages].body_is_final) {
		fprintf(stderr, "\n\n *** Error http_body_is_final() should return 1 "
			"on last on_body callback call "
			"but it doesn't! ***\n\n");
		assert(0);
		abort();
	}
	messages[num_messages].body_is_final = http_body_is_final(p);
}

int body_cb(http_parser* p, const char* buf, size_t len)
{
	assert(p == parser);
	strlncat(messages[num_messages].body, sizeof(messages[num_messages].body), buf, len);
	messages[num_messages].body_size += len;
	check_body_is_final(p);
	return 0;
}

int headers_complete_cb(http_parser* p)
{
	assert(p == parser);
	messages[num_messages].method = (http_method)parser->method;
	messages[num_messages].status_code = parser->status_code;
	messages[num_messages].http_major = parser->http_major;
	messages[num_messages].http_minor = parser->http_minor;
	messages[num_messages].headers_complete_cb_called = true;
	messages[num_messages].should_keep_alive = http_should_keep_alive(parser);
	return 0;
}

int message_complete_cb(http_parser* p)
{
	assert(p == parser);
	if (messages[num_messages].should_keep_alive != http_should_keep_alive(parser)) {
		fprintf(stderr, "\n\n *** Error http_should_keep_alive() should have same "
			"value in both on_message_complete and on_headers_complete "
			"but it doesn't! ***\n\n");
		assert(0);
		abort();
	}

	if (messages[num_messages].body_size && http_body_is_final(p) && !messages[num_messages].body_is_final) {
		fprintf(stderr, "\n\n *** Error http_body_is_final() should return 1 "
			"on last on_body callback call "
			"but it doesn't! ***\n\n");
		assert(0);
		abort();
	}

	messages[num_messages].message_complete_cb_called = true;
	messages[num_messages].message_complete_on_eof = currently_parsing_eof;
	num_messages++;
	return 0;
}

int chunk_header_cb(http_parser* p)
{
	assert(p == parser);
	int chunk_idx = messages[num_messages].num_chunks;
	messages[num_messages].num_chunks++;
	if (chunk_idx < MAX_CHUNKS) {
		messages[num_messages].chunk_lengths[chunk_idx] = p->content_length;
	}

	return 0;
}

int chunk_complete_cb(http_parser* p)
{
	assert(p == parser);

	/* Here we want to verify that each chunk_header_cb is matched by a
	* chunk_complete_cb, so not only should the total number of calls to
	* both callbacks be the same, but they also should be interleaved
	* properly */
	assert(messages[num_messages].num_chunks == messages[num_messages].num_chunks_complete + 1);

	messages[num_messages].num_chunks_complete++;
	return 0;
}

http_parser_settings settings_null = { nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr };
http_parser_settings settings = { message_begin_cb, request_url_cb, response_status_cb, header_field_cb, header_value_cb,
				headers_complete_cb, body_cb, message_complete_cb, chunk_header_cb, chunk_complete_cb };
http_parser_settings settings_count_body = {};/*{ message_begin_cb, request_url_cb, response_status_cb, header_field_cb, header_value_cb,
				headers_complete_cb, count_body_cb, message_complete_cb, chunk_header_cb, chunk_complete_cb};*/
http_parser_settings settings_pause = {};/* { pause_message_begin_cb, pause_request_url_cb, pause_response_status_cb, pause_header_field_cb, pause_header_value_cb
				pause_headers_complete_cb, pause_body_cb, pause_message_complete_cb, pause_chunk_header_cb, pause_chunk_complete_cb};*/

int test_no_overflow_long_body(int req, size_t length)
{
	http_parser parser;
	http_parser_init(&parser, req ? HTTP_REQUEST : HTTP_RESPONSE);
	char buf1[3000];
	size_t buf1len = sprintf(buf1, "%s\r\nConnection: Keep-Alive\r\nContent-Length: %lu\r\n\r\n",
		req ? "POST / HTTP/1.0" : "HTTP/1.0 200 OK", (unsigned long)length);
	size_t parsed = http_parser_execute(&parser, &settings_null, buf1, buf1len);
	if (parsed != buf1len) return -1;

	for (size_t i = 0; i < length; i++) {
		char foo = 'a';
		parsed = http_parser_execute(&parser, &settings_null, &foo, 1);
		if (parsed != 1) return -1;
	}

	parsed = http_parser_execute(&parser, &settings_null, buf1, buf1len);
	if (parsed != buf1len) return -1;

	return 0;
}

void parser_init(http_parser_type type)
{
	num_messages = 0;
	assert(parser == NULL);
	parser = (http_parser*)malloc(sizeof(http_parser));
	http_parser_init(parser, type);
	memset(&messages, 0, sizeof messages);
}

void parser_free()
{
	assert(parser);
	free(parser);
	parser = NULL;
}

size_t parse(const char* buf, size_t len)
{
	size_t nparsed;
	currently_parsing_eof = (len == 0);
	nparsed = http_parser_execute(parser, &settings, buf, len);
	return nparsed;
}

//size_t parse_count_body(const char *buf, size_t len)
//{
//	size_t nparsed;
//	currently_parsing_eof = (len == 0);
//	nparsed = http_parser_execute(parser, &settings_count_body, buf, len);
//	return nparsed;
//}

//size_t parse_pause(const char *buf, size_t len)
//{
//	size_t nparsed;
//	http_parser_settings s = settings_pause;
//
//	currently_parsing_eof = (len == 0);
//	current_pause_parser = &s;
//	nparsed = http_parser_execute(parser, current_pause_parser, buf, len);
//	return nparsed;
//}

//size_t parse_connect(const char *buf, size_t len)
//{
//	size_t nparsed;
//	currently_parsing_eof = (len == 0);
//	nparsed = http_parser_execute(parser, &settings_connect, buf, len);
//	return nparsed;
//}

int test_simple_type(const char* buf, http_errno err_expected, http_parser_type type)
{
	parser_init(type);
	parse(buf, strlen(buf));
	http_errno err = HTTP_PARSER_ERRNO(parser);
	parse(NULL, 0);
	parser_free();

	// In strict mode, allow us to pass with an unexpected HPE_STRICT as long as the caller isn't expecting success.
	if (err_expected != err && err_expected != HPE_OK && err != HPE_STRICT) {
		fprintf(stderr, "\n*** test_simple expected %s, but saw %s ***\n\n%s\n", http_errno_name(err_expected), http_errno_name(err), buf);
		return -1;
	}

	return 0;
}

} // namespace

int test_http_parser()
{
	// reference: http-parser/test.c
{ // get http-parser version
	unsigned long version = http_parser_version();
	unsigned int major = (version >> 16) & 255;
	unsigned int minor = (version >> 8) & 255;
	unsigned int patch = version & 255;
	fprintf(stdout, "http_parser version: %u.%u.%u\n", major, minor, patch);
}

{ // test preserve data
	char my_data[] = "application-specific data";
	http_parser parser;
	parser.data = my_data;
	http_parser_init(&parser, HTTP_REQUEST);
	if (parser.data != my_data) {
		fprintf(stderr, "\n*** parser.data not preserved accross http_parser_init ***\n\n");
		return -1;
	}
}

{ // test method str
	const char* str1 = http_method_str(HTTP_GET);
	const char* str2 = http_method_str((http_method)1337);
	fprintf(stdout, "http method: str1: %s, str2: %s\n", str1, str2);
}

{ // test header nread value
	http_parser parser;
	http_parser_init(&parser, HTTP_REQUEST);
	const char* buf = "GET / HTTP/1.1\r\nheader: value\nhdr: value\r\n";
	size_t len = strlen(buf);
	size_t parsed = http_parser_execute(&parser, &settings_null, buf, len);
	if (parsed != len || parser.nread != len) {
		fprintf(stderr, "fail to http_parser_execute: parsed: %d, len: %d, parser.nread: %d\n", parsed, len, parser.nread);
		return -1;
	}
}

{ // test no overflow parse url
	http_parser_url u;
	http_parser_url_init(&u);
	int rv = http_parser_parse_url("http://example.com:8001", 22, 0, &u);
	if (rv != 0 || u.port != 800) {
		fprintf(stderr, "return value: %d, prot number: %d\n", rv, u.port);
		return -1;
	}
}

{ // test no overflow long body
	if (test_no_overflow_long_body(HTTP_REQUEST, 1000) || test_no_overflow_long_body(HTTP_REQUEST, 100000) ||
		test_no_overflow_long_body(HTTP_RESPONSE, 1000) || test_no_overflow_long_body(HTTP_RESPONSE, 100000)) {
		fprintf(stderr, "fail to test no overflow long body\n");
		return -1;
	}
}

{ // test simple type
	if (test_simple_type(
		"POST / HTTP/1.1\r\n"
		"Content-Length:  42 \r\n"  // Note the surrounding whitespace.
		"\r\n",
		HPE_OK,
		HTTP_REQUEST)) {
		fprintf(stderr, "fail to test simple type\n");
		return -1;
	}
}

	return 0;
}

//////////////////////////////////////////////////////////
namespace {
void dump_url(const char *url, const struct http_parser_url *u)
{
	fprintf(stdout, "\tfield_set: 0x%x, port: %u\n", u->field_set, u->port);
	for (unsigned int i = 0; i < UF_MAX; ++i) {
		if ((u->field_set & (1 << i)) == 0) {
			fprintf(stdout, "\tfield_data[%u]: unset\n", i);
			continue;
		}

		fprintf(stdout, "\tfield_data[%u]: off: %u, len: %u, part: %.*s\n", i,
			u->field_data[i].off, u->field_data[i].len, u->field_data[i].len, url + u->field_data[i].off);
	}
}
} // namespace

int test_http_parser_url()
{
	// reference: http-parser/contrib/url_parser.c
//{ // connect
//	int argc = 3;
//	char* argv[] = { "", "connect", "https://xxx.xxx.xxx" };
//	
//	int connect = strcmp("connect", argv[1]) == 0 ? 1 : 0;
//	fprintf(stdout, "Parsing: %s, connect: %d\n", argv[2], connect);
//
//	struct http_parser_url u;
//	http_parser_url_init(&u);
//
//	int len = strlen(argv[2]);
//	int result = http_parser_parse_url(argv[2], len, connect, &u);
//	if (result != 0) {
//		fprintf(stderr, "Parse error : %d\n", result);
//		return result;
//	}
//
//	fprintf(stdout, "Parse ok, result : \n");
//	dump_url(argv[2], &u);
//}

{ // get
	int argc = 3;
	char* argv[] = { "", "get", "https://blog.csdn.net/fengbingchun" };

	int connect = strcmp("connect", argv[1]) == 0 ? 1 : 0;
	fprintf(stdout, "Parsing: %s, connect: %d\n", argv[2], connect);

	struct http_parser_url u;
	http_parser_url_init(&u);

	int len = strlen(argv[2]);
	int result = http_parser_parse_url(argv[2], len, connect, &u);
	if (result != 0) {
		fprintf(stderr, "Parse error : %d\n", result);
		return result;
	}

	fprintf(stdout, "Parse ok, result : \n");
	dump_url(argv[2], &u);
}

	return 0;
}

