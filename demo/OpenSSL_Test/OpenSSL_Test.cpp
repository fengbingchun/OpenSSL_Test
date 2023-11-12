#include <iostream>
#include "funset.hpp"

int main()
{
	auto ret = test_sockpp_server();

	if (ret == 0) std::cout << "========== test success ==========\n";
	else std::cerr << "########## test fail ##########\n";

	return 0;
}
