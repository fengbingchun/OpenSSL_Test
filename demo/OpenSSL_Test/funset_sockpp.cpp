#include <chrono>
#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <thread>
#include <map>
#include <atomic>

#ifdef __linux__
#ifdef INVALID_SOCKET
#undef INVALID_SOCKET
#endif
#endif

#include <sockpp/tcp_acceptor.h>
#include <sockpp/tcp_connector.h>

#include "funset.hpp"

// Blog: https://blog.csdn.net/fengbingchun/article/details/134359922

namespace {

constexpr char* host{"127.0.0.1"};
constexpr in_port_t port{ 8888 };
constexpr int len {64};

void run_echo(sockpp::tcp_socket sock)
{
	std::cout << "thread id: " << std::this_thread::get_id() << std::endl;

	std::map<std::string, std::string> addr;
	addr["csdn"] = "https://blog.csdn.net/fengbingchun";
	addr["github"] = "https://github.com/fengbingchun";

	std::unique_ptr<unsigned char[]> buf(new unsigned char[len]);

	while (true) {
		memset(buf.get(), 0, len);
		auto ret = sock.read(buf.get(), len);
		if (ret == -1) {
			std::cerr << "Error: reading from TCP stream: " << sock.last_error_str() << std::endl;
            break;
		}

		auto it = addr.find(std::string((char*)buf.get()));
		if (it != addr.end()) {
			sock.write(it->second);
		}
		else
			sock.write("unkonwn");
	}
}

} // namespace

int test_sockpp_client()
{
    sockpp::initialize();

    sockpp::tcp_connector conn({host, port});
	if (!conn) {
		std::cerr << "Error: connecting to server at: "
			<< sockpp::inet_address(host, port)
			<< ", message: " << conn.last_error_str() << std::endl;
		return -1;
	}

    std::cout << "created a connection from: " << conn.address() << std::endl;
	std::cout << "created a connection to " << conn.peer_address() << std::endl;

    // set a timeout for the responses
    if (!conn.read_timeout(std::chrono::seconds(5))) {
        std::cerr << "Error: setting timeout on TCP stream: " << conn.last_error_str() << std::endl;
    }

    const std::vector<std::string> addr{"csdn", "github", "gitlab"};
    std::unique_ptr<unsigned char[]> buf(new unsigned char[len]);
    int index{0};

	std::atomic<bool> quit{ false };
	std::thread th([&quit] {
		std::this_thread::sleep_for(std::chrono::seconds(20));
		quit = true;
	});

	while (true) {
		if (quit) break;

        auto ret = conn.write(addr[index]);
        if (ret != addr[index].size()) {
            std::cerr << "Error: writing to the TCP stream: " << conn.last_error_str() << std::endl;
            break;
        }

		memset(buf.get(), 0, len);
        ret = conn.read(buf.get(), len);
        if (ret == -1) {
            std::cerr << "Error: reading from TCP stream: " << conn.last_error_str() << std::endl;
            break;
        }

        std::cout << addr[index] << ": " << buf.get() << std::endl;

        if (++index == addr.size()) index = 0;
		std::this_thread::sleep_for(std::chrono::seconds(1));
	}

	th.join();
    return 0;
}

int test_sockpp_server()
{
    sockpp::initialize();

    sockpp::tcp_acceptor acc(port);
	if (!acc) {
		std::cerr << "Error: creating the acceptor: " << acc.last_error_str() << std::endl;
		return -1;
	}

	while (true) {
		sockpp::inet_address peer;
		// accept a new client connection
		sockpp::tcp_socket sock = acc.accept(&peer);
		std::cout << "received a connection request from: " << peer << std::endl;
		if (!sock) {
			std::cerr << "Error: accepting incoming connection: " << acc.last_error_str() << std::endl;
		}
		else {
			// create a thread and transfer the new stream to it
			std::thread th2(run_echo, std::move(sock));
			th2.detach();
		}
	}

    return 0;
}
