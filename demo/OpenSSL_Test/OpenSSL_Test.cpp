#include <iostream>
#include "funset.hpp"

int main()
{
	int ret = test_socket_tcp_server();

	if (0 == ret) fprintf(stdout, "========== test success ==========\n");
	else fprintf(stderr, "########## test fail ##########\n");

	return 0;
}

