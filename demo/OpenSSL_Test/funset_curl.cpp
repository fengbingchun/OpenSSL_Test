#include "funset.hpp"
#include <iostream>
#include <curl/curl.h>

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
	const char* outfilename = "E:/GitCode/OpenSSL_Test/out.jpg";
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

