#include "funset.hpp"
#ifdef _MSC_VER
#include <WinSock2.h>
#include <winsock.h>
#else
#include <sys/select.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#endif
#include <iostream>

// Blog: https://blog.csdn.net/fengbingchun/article/details/100834902

int test_select_1()
{
#ifdef _MSC_VER
	fd_set fds;
	FD_ZERO(&fds);

	timeval tv;
	tv.tv_sec = 2;
	tv.tv_usec = 0;

	int ret = select(0, &fds, nullptr, nullptr, &tv);
	if (ret == SOCKET_ERROR) {
		fprintf(stderr, "fail to select, error: %d\n", WSAGetLastError());
		return -1;
	} else if (ret == 0) {
		fprintf(stderr, "select timeout\n");
		return -1;
	} else {
		fprintf(stdout, "success to select\n");
	}
#else
	const char* path = "/dev/video0";
	int fd = open(path, O_RDWR);
	if (fd == -1) {
		fprintf(stderr, "fail to open device: %s\n", path);
	}

	fd_set fds;
	FD_ZERO(&fds);
	FD_SET(fd, &fds);

	struct timeval tv;
	tv.tv_sec = 2;
	tv.tv_usec = 0;

	int ret = select(fd+1, &fds, nullptr, nullptr, &tv);
	if (ret == -1) {
		fprintf(stderr, "fail to select, error: %d, %s\n", errno, strerror(errno));
		return -1;
	} else if (ret == 0) {
		fprintf(stderr, "select timeout\n");
		return -1;
	} else {
		fprintf(stdout, "success to select\n");
	}

	close(fd);
#endif

	return 0;
}


