#! /bin/bash

if [ $# != 2 ]; then
    echo "Error: requires two parameters: 1: windows or linux; 2: release or debug"
    echo "For example: $0 windows debug"
    exit -1
fi

if [ $1 != "windows"  ] && [ $1 != "linux" ]; then
    echo "Error: the first parameter can only be windows or linux"
    exit -1
fi

if [ $2 != "debug" ] && [ $2 != "release" ]; then
    echo "Error: the second parameter can only be debug or release"
    exit -1
fi

if [ $1 == "windows" ] && [ $2 == "debug" ]; then
    cmake \
        -G"Visual Studio 17 2022" -A x64 \
        -DCMAKE_BUILD_TYPE=Debug \
        -DCMAKE_CONFIGURATION_TYPES=Debug \
        -DSOCKPP_BUILD_SHARED=OFF \
        -DSOCKPP_BUILD_STATIC=ON \
        -DSOCKPP_BUILD_EXAMPLES=ON \
        -DCMAKE_INSTALL_PREFIX=install/debug \
        -Bbuild \
        .
    
    cmake --build build/ --target install --config debug
fi

if [ $1 == "windows" ] && [ $2 == "release" ]; then
    cmake \
        -G"Visual Studio 17 2022" -A x64 \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_CONFIGURATION_TYPES=Release \
        -DSOCKPP_BUILD_SHARED=OFF \
        -DSOCKPP_BUILD_STATIC=ON \
        -DSOCKPP_BUILD_EXAMPLES=ON \
        -DCMAKE_INSTALL_PREFIX=install/release \
        -Bbuild \
        .

    cmake --build build/ --target install --config release
fi

if [ $1 == "linux" ] && [ $2 == "debug" ]; then
    cmake \
        -DCMAKE_BUILD_TYPE=Debug \
        -DSOCKPP_BUILD_SHARED=OFF \
        -DSOCKPP_BUILD_STATIC=ON \
        -DSOCKPP_BUILD_EXAMPLES=ON \
        -DCMAKE_INSTALL_PREFIX=install/debug \
        -Bbuild \
        .
    
    cmake --build build/ --target install --config debug
fi

if [ $1 == "linux" ] && [ $2 == "release" ]; then
    cmake \
        -DCMAKE_BUILD_TYPE=Release \
        -DSOCKPP_BUILD_SHARED=OFF \
        -DSOCKPP_BUILD_STATIC=ON \
        -DSOCKPP_BUILD_EXAMPLES=ON \
        -DCMAKE_INSTALL_PREFIX=install/release \
        -Bbuild \
        .

    cmake --build build/ --target install --config release
fi

rc=$?
if [[ ${rc} != 0 ]]; then
    echo "Error: please check: ${rc}"
	exit ${rc}
fi
