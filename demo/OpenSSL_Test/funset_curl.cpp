#include "funset.hpp"
#include <string.h>
#include <iostream>
#include <curl/curl.h>
#include "common.hpp"

// Blog: https://blog.csdn.net/fengbingchun/article/details/124380859
namespace {

// reference: https://stackoverflow.com/questions/2329571/c-libcurl-get-output-into-a-string
struct String {
	char* ptr;
	size_t len;
};

void init_string(struct String* s)
{
	s->len = 0;
	s->ptr = (char*)malloc(s->len + 1);
	if (s->ptr == nullptr) {
		fprintf(stderr, "failed to malloc\n");
		exit(EXIT_FAILURE);
	}
	s->ptr[0] = '\0';
}

size_t write_func(void* ptr, size_t size, size_t nmemb, struct String* s)
{
	size_t new_len = s->len + size*nmemb;
	s->ptr = (char*)realloc(s->ptr, new_len + 1);
	if (s->ptr == nullptr) {
		fprintf(stderr, "failed to realloc\n");
		exit(EXIT_FAILURE);
	}
	memcpy(s->ptr + s->len, ptr, size*nmemb);
	s->ptr[new_len] = '\0';
	s->len = new_len;

	return size*nmemb;
}

} // namespace

int test_curl_proxy_http()
{
	CURL* curl = curl_easy_init(); // 开始一个libcurl简单会话
	if (curl) {
		struct String s;
		init_string(&s);

		// 存放服务器响应内容
		CHECK(curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_func) == CURLE_OK);
		CHECK(curl_easy_setopt(curl, CURLOPT_WRITEDATA, &s) == CURLE_OK);

		CHECK(curl_easy_setopt(curl, CURLOPT_URL, "https://license.xxxx.com/api/v2/health") == CURLE_OK); // 服务器地址
		CHECK(curl_easy_setopt(curl, CURLOPT_PROXY, "https://licenseproxytest.xxxx.com:9999") == CURLE_OK); // 代理服务器地址:端口
		CHECK(curl_easy_setopt(curl, CURLOPT_HTTPPROXYTUNNEL, 1L) == CURLE_OK); // 使用HTTP管道方式
		CHECK(curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L) == CURLE_OK); // 输出较详细信息
		CHECK(curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10) == CURLE_OK); // 设置超时时间10秒
		//CHECK(curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L) == CURLE_OK); // 不验证证书
#if _MSC_VER
		// windows找不到证书,需要显示指定否则调用curl_easy_perform会返回60;只有CURLOPT_SSL_VERIFYPEER设为true时此句才会生效
		// 在Linux下会默认查找证书位置:/etc/ssl/certs/
		CHECK(curl_easy_setopt(curl, CURLOPT_CAINFO, "../../../testdata/ca-bundle.crt") == CURLE_OK); // 带有服务器端公钥的证书
#endif
		//CHECK(curl_easy_setopt(curl, CURLOPT_SSLCERT, ".pem") == CURLE_OK); // 客户端证书
		//CHECK(curl_easy_setopt(curl, CURLOPT_SSLKEY, ".pem") == CURLE_OK); // 客户端私钥

		struct curl_slist* headers = nullptr;
		headers = curl_slist_append(headers, "Proxy-Connection: Keep-Alive"); // 将字符串附加到链表
		CHECK(curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers) == CURLE_OK); // header链表

		CURLcode curl_code = curl_easy_perform(curl); // 以阻塞方式执行整个请求,并在完成时返回,如果失败则更早返回
		if (curl_code != CURLE_OK) {
			fprintf(stderr, "failed to curl_easy_perform: %d\n", curl_code);
			return -1;
		}

		long value = 0;
		curl_code = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &value); // 提取信息
		if (curl_code != CURLE_OK) {
			fprintf(stderr, "failed to curl_easy_getinfo: %d\n", curl_code);
			return -1;
		}

		fprintf(stdout, "response: %s\n", s.ptr); // json格式
		free(s.ptr);

		curl_easy_cleanup(curl); // 结束libcurl会话
		return 0;
	}

	return -1;
}

/////////////////////////////////////////////////////////////////////
// Blog: https://blog.csdn.net/fengbingchun/article/details/48007563
namespace {
size_t callbackfunction(void *ptr, size_t size, size_t nmemb, void* userdata)
{
	FILE* stream = (FILE*)userdata;
	if (!stream) {
		fprintf(stderr, "Error: no stream\n");
		return 0;
	}

	size_t written = fwrite((FILE*)ptr, size, nmemb, stream);
	return written;
}

} // namespace

int test_curl_download_image_1()
{
	const char* url = "http://www.xinhuanet.com/photo/2018-11/18/1123730698_15425193202431n.jpg";
#ifdef __linux__
	const char* outfilename = "out.jpg";
#else
	const char* outfilename = "../../../out.jpg";
#endif

	FILE* fp = fopen(outfilename, "wb");
	if (!fp) {
		fprintf(stderr, "Failed to create file on the disk\n");
		return -1;
	}

	CURL* curlCtx = curl_easy_init();
	curl_easy_setopt(curlCtx, CURLOPT_URL, url);
	curl_easy_setopt(curlCtx, CURLOPT_WRITEDATA, fp);
	curl_easy_setopt(curlCtx, CURLOPT_WRITEFUNCTION, callbackfunction);
	curl_easy_setopt(curlCtx, CURLOPT_FOLLOWLOCATION, 1);

	CURLcode rc = curl_easy_perform(curlCtx);
	if (rc) {
		fprintf(stderr, "Failed to download image: %s\n", url);
		return -1;
	}

	long res_code = 0;
	curl_easy_getinfo(curlCtx, CURLINFO_RESPONSE_CODE, &res_code);
	if (!((res_code == 200 || res_code == 201) && rc != CURLE_ABORTED_BY_CALLBACK)) {
		fprintf(stderr, "Response error, code: %d\n", res_code);
		return -1;
	}

	curl_easy_cleanup(curlCtx);
	fclose(fp);

	return 0;
}

