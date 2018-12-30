#! /bin/bash

real_path=$(realpath $0)
dir_name=`dirname "${real_path}"`
echo "real_path: ${real_path}, dir_name: ${dir_name}"

new_dir_name=${dir_name}/build
mkdir -p ${new_dir_name}
cd ${new_dir_name}
echo "pos: ${new_dir_name}"
if [ "$(ls -A ${new_dir_name})" ]; then
	echo "directory is not empty: ${new_dir_name}"
	#rm -r *
else
	echo "directory is empty: ${new_dir_name}"
fi

cd -
# build libcurl
echo "========== start build libcurl =========="
libcurl_path=${dir_name}/../../src/curl
if [ -f ${curl_path}/build/lib/libcurl.so ]; then
	echo "libcurl dynamic library already exists without recompiling"
else
	mkdir -p ${libcurl_path}/build
	cd ${libcurl_path}/build
	cmake  -DBUILD_SHARED_LIBS=ON ..
	make
fi

ln -s ${libcurl_path}/build/lib/libcurl* ${new_dir_name}
echo "========== finish build libcurl =========="

rc=$?
if [[ ${rc} != 0 ]]; then
	echo "########## Error: some of thess commands have errors above, please check"
	exit ${rc}
fi

cd -
cd ${new_dir_name}
cmake ..
make

cd -

