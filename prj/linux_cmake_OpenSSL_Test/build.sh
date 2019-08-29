#! /bin/bash

real_path=$(realpath $0)
echo "real_path: ${real_path}"
dir_name=`dirname "${real_path}"`
echo "dir_name: ${dir_name}"

new_dir_name=${dir_name}/build
if [[ -d ${new_dir_name} ]]; then
	echo "directory already exists: ${new_dir_name}"
else
	echo "directory does not exist: ${new_dir_name}, need to create"
	mkdir -p ${new_dir_name}
fi

# build libcurl
echo "========== start build libcurl =========="
libcurl_path=${dir_name}/../../src/curl
if [ -f ${libcurl_path}/build/lib/libcurl.so ]; then
	echo "libcurl dynamic library already exists without recompiling"
else
	mkdir -p ${libcurl_path}/build
	cd ${libcurl_path}/build
	cmake  -DBUILD_SHARED_LIBS=ON ..
	make

	cd -
fi

cp ${libcurl_path}/build/lib/libcurl* ${new_dir_name}
echo "========== finish build libcurl =========="

rc=$?
if [[ ${rc} != 0 ]]; then
	echo "########## Error: some of thess commands have errors above, please check"
	exit ${rc}
fi

cd ${new_dir_name}
cmake ..
make

cd -
