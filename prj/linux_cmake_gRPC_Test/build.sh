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

# copy gRPC libraries
echo "========== start copy grpc =========="
libgrpc_path=${dir_name}/../../src/grpc
cp -a ${libgrpc_path}/linux_install/lib/*.a ${new_dir_name}
cp -a ${libgrpc_path}/linux_install/bin/protoc ${new_dir_name}
echo "========== finish copy libgrpc =========="

rc=$?
if [[ ${rc} != 0 ]]; then
	echo "########## Error: some of thess commands have errors above, please check"
	exit ${rc}
fi

cd ${new_dir_name}
cmake ..
make

cd -
