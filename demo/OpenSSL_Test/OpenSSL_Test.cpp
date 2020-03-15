#include <iostream>
#include "funset.hpp"

int main()
{
	int ret = test_bearssl_1();

	if (0 == ret) fprintf(stdout, "========== test success ==========\n");
	else fprintf(stderr, "########## test fail ##########\n");

	return 0;
}

