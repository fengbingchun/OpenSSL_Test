#! /bin/bash

real_path=$(realpath $0)
echo "real_path: ${real_path}"
dir_name=`dirname "${real_path}"`
echo "dir_name: ${dir_name}"

data_dir="testdata"
if [ -d ${dir_name}/${data_dir} ]; then
	rm -rf ${dir_name}/${data_dir}
fi
ln -s ${dir_name}/./../../${data_dir} ${dir_name}

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

# build bearssl
echo "========== start build BearSSL =========="
bearssl_path=${dir_name}/../../src/bearssl
if [ -f ${bearssl_path}/build/libbearssl.so ]; then
	echo "bearssl dynamic library already exists without recompiling"
else
	cd ${bearssl_path}
	make

	cd -
fi

cp ${bearssl_path}/build/libbearssl.so ${new_dir_name}
echo "========== finish build bearssl =========="

# build openssl
echo "========== start build openssl =========="
openssl_path=${dir_name}/../../src/openssl
if [[ -f ${openssl_path}/build/install/lib/libcrypto.so.1.1 && -f ${openssl_path}/build/install/lib/libssl.so.1.1 ]]; then
	echo "openssl dynamic library already exists without recompiling"
else
	mkdir -p ${openssl_path}/build
	cd ${openssl_path}/build
	.././config --prefix=${openssl_path}/build/install
	make
	make install

	cd -
fi

cp ${openssl_path}/build/install/lib/libcrypto.so.1.1 ${new_dir_name}
cp ${openssl_path}/build/install/lib/libssl.so.1.1 ${new_dir_name}

rc=$?
if [[ ${rc} != 0 ]]; then
	echo "########## Error: some of thess commands have errors above, please check"
	exit ${rc}
fi

cd ${new_dir_name}
cmake ..
make

cd -
