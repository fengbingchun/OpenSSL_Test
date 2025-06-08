#ifdef _MSC_VER
#include <iostream>
#include <fstream>
#include <string>
#include <memory>
#include <filesystem>
#include <chrono>
#include <tuple>
#include <format>
#include <hv/HttpServer.h>
#include <hv/HttpService.h>
#include <hv/HttpClient.h>
#include <hv/HttpMessage.h>
#include <hv/base64.h>

// Blog: https://blog.csdn.net/fengbingchun/article/details/148513653
int test_libhv_http_client_diet()
{
	constexpr char file_name[]{ "../../../testdata/diet.json" };
	std::ifstream in_file(file_name);
	if (!in_file.is_open()) {
		std::cerr << "Error: failed to open json file: " << file_name << std::endl;
		return -1;
	}

	auto j = hv::Json::parse(in_file);
	constexpr int number{ 5 };
	j["number"] = number;

	const std::string server_url{ "http://192.168.1.28:8000" };
	HttpRequest request{};
	request.method = HTTP_POST;
	request.url = server_url + "/api/optimize";
	request.body = j.dump();
	request.headers["Content-Type"] = "application/json";
	request.timeout = 2;

	hv::HttpClient client{};
	HttpResponse response{};
	if (auto ret = client.send(&request, &response); ret == 0) {
		if (response.status_code == HTTP_STATUS_OK) {
			hv::Json j = hv::Json::parse(response.body);
			std::cout << "result: " << j.dump() << std::endl;

			constexpr char result_name[]{ "../../../testdata/result.json" };
			std::ofstream out_file(result_name);
			if (!out_file.is_open()) {
				std::cerr << "Error: faild to open file: " << result_name << std::endl;
				return -1;
			}
			out_file << j.dump(2);
		} else {
			std::cerr << "status code: " << response.status_code << ", status message: " << response.status_message() << ", body: " << response.body << std::endl;
			return -1;
		}
	} else {
		std::cerr << "Error: failed to send, error code: " << ret << std::endl;
		return -1;
	}

	return 0;
}

/////////////////////////////////////////////////////////////////
// Blog: https://blog.csdn.net/fengbingchun/article/details/148479474
int test_libhv_http_client()
{
	const std::string server_url{ "http://192.168.19.205:8080" };
	HttpRequest request{};
	request.method = HTTP_GET;
	request.url =  server_url + "/api/test1";

	hv::HttpClient client{};
	HttpResponse response{};
	if (auto ret = client.send(&request, &response); ret == 0) {
		auto j = hv::Json::parse(response.body);
		if (j.contains("time")) {
			std::cout << "server time: " << j["time"] << std::endl;
		} else {
			std::cerr << "Error: missing time field: " << response.body << std::endl;
		}
	} else {
		std::cerr << "Error: failed to request: " << ret << std::endl;
	}

	constexpr char image_name[]{ "../../../testdata/cat.jpg" };
	std::ifstream in_file(image_name, std::ios::binary | std::ios::ate); 
	if (!in_file.is_open()) {
		std::cerr << "Error: fail to open file: " << image_name << std::endl;
		return -1;
	}

	size_t file_size = in_file.tellg();
	std::unique_ptr<unsigned char[]> data(new unsigned char[file_size]);
	in_file.seekg(0);
	in_file.read(reinterpret_cast<char*>(data.get()), file_size);

	auto base64_data = hv::Base64Encode(data.get(), file_size);

	hv::Json j = {
		{"image_name", image_name},
		{"image_data", base64_data},
		{"image_size", file_size}
	};

	HttpRequest request2{};
	request2.method = HTTP_POST;
	request2.url = server_url + "/api/test2";
	request2.body = j.dump();
	request2.headers["Content-Type"] = "application/json";
	request2.timeout = 2;

	HttpResponse response2{};
	if (auto ret = client.send(&request2, &response2); ret == 0) {
		if (response2.status_code == HTTP_STATUS_OK) { // 200
			hv::Json j = hv::Json::parse(response2.body);
			if (!j.contains("image_size") || !j.contains("image_time")) {
				std::cerr << "Error: missing image_size or image_time: " << response2.body << std::endl;
				return -1;
			}
			std::cout << "image was created at: " << j["image_time"] << ", image size: " << j["image_size"] << std::endl;
		} else {
			std::cerr << "status code: " << response2.status_code << ", status message: " << response2.status_message() << ", body: " << response2.body << std::endl;
			return -1;
		}
	} else {
		std::cerr << "Error: failed to send, error code: " << ret << std::endl;
		return -1;
	}

	return 0;
}

int test_libhv_http_server()
{
	namespace fs = std::filesystem;

	hv::HttpService router{};
	router.GET("/api/test1", [](const HttpContextPtr& ctx) {
		std::cout << "client: ip addr: " << ctx->ip() << ", port: " << ctx->port() << ", method: " << ctx->method() << std::endl;

		auto get_local_time = [] {
			auto time = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
			std::tm* tm = std::localtime(&time);

			std::stringstream buffer;
			buffer << std::put_time(tm, "%Y-%m-%d %H:%M:%S");
			return buffer.str();
		};

		hv::Json j = {
			{"status", "success"},
			{"time", get_local_time()}
		};
		return ctx->send(j.dump());
	});

	router.POST("/api/test2", [](const HttpContextPtr& ctx) {
		try {
			std::cout << "client: ip addr: " << ctx->ip() << ", port: " << ctx->port() << ", method: " << ctx->method() << std::endl;

			auto j = hv::Json::parse(ctx->body());
			if (!j.contains("image_name") || !j.contains("image_data") || !j.contains("image_size")) {
				ctx->setStatus(HTTP_STATUS_BAD_REQUEST);
				return ctx->send(R"({"error":"missing image_name or image_data or image_size"})");
			}

			auto data = hv::Base64Decode(j["image_data"].get<std::string>().c_str());
			if (data.length() != j["image_size"]) {
				ctx->setStatus(HTTP_STATUS_PRECONDITION_FAILED);
				return ctx->send(R"({"error":"data length mismatch"})");
			}

			fs::path image_path = j["image_name"].get<std::string>();
			auto image_name = image_path.filename();
			std::ofstream out_file(image_name.string(), std::ios::binary);
			out_file.write(data.data(), data.length());
			out_file.close();

			auto get_time = [](fs::file_time_type tp) {
				using namespace std::chrono;
				auto sctp = time_point_cast<system_clock::duration>(tp - fs::file_time_type::clock::now() + system_clock::now());
				auto tt = system_clock::to_time_t(sctp);

				std::tm* gmt = std::localtime(&tt); // UTC: std::gmtime(&tt);
				std::stringstream buffer;
				buffer << std::put_time(gmt, "%Y-%m-%d %H:%M:%S");
				return buffer.str();
			};

			auto image_time = get_time(fs::last_write_time(image_name));
			std::cout << "image was created at: " << image_time << std::endl;

			auto get_file_size = [](std::uintmax_t size) {
				float s1 = size / 1024. / 1024 / 1024;
				float s2 = size / 1024. / 1024;
				float s3 = size / 1024.;

				if (s1 > 1)
					return std::make_tuple(s1, std::string(" GB"));
				if (s2 > 1)
					return std::make_tuple(s2, std::string(" MB"));
				if (s3 > 1)
					return std::make_tuple(s3, std::string(" KB"));

				return std::make_tuple(static_cast<float>(size), std::string(" Bytes"));
			};

			auto [image_size, suffix] = get_file_size(static_cast<std::intmax_t>(fs::file_size(image_name)));
			std::cout << "image size: " << image_size << suffix << std::endl;

			ctx->setContentType(APPLICATION_JSON);
			hv::Json j2 = {
				{"status", "success"},
				{"image_time", image_time},
				{"image_size", std::format("{:.4f}{}", image_size, suffix)}
			};
			return ctx->send(j2.dump());
		} catch (const std::exception& e) {
			ctx->setStatus(HTTP_STATUS_INTERNAL_SERVER_ERROR);
			hv::Json j3 = { "error", e.what() };
			return ctx->send(j3.dump());
		}
	});

	hv::HttpServer server{};
	server.port = 8080;
	//server.worker_threads = 2;
	server.service = &router;

	//server.run(); // blocking
	server.start(); // non-blocking
	while (true) {
		hv_delay(1000);
	}

	return 0;
}

# endif // _MSC_VER
