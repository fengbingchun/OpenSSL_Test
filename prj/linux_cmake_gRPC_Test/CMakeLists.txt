PROJECT(gRPC_Test)
CMAKE_MINIMUM_REQUIRED(VERSION 3.0)

# support C++11
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11")
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
# support C++14, when gcc version > 5.1, use -std=c++14 instead of c++1y
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++1y")

IF(NOT CMAKE_BUILD_TYPE)
	SET(CMAKE_BUILD_TYPE "Release")
	SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -O2")
	SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -O2")
ELSE()
	SET(CMAKE_BUILD_TYPE "Debug")
	SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -Wall -O2")
	SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -Wall -O2")
ENDIF()
MESSAGE(STATUS "cmake build type: ${CMAKE_BUILD_TYPE}")

MESSAGE(STATUS "cmake current source dir: ${CMAKE_CURRENT_SOURCE_DIR}")
SET(PATH_TEST_FILES ${CMAKE_CURRENT_SOURCE_DIR}/./../../demo/gRPC_Test)
SET(PATH_SRC_GRPC_FILES ${CMAKE_CURRENT_SOURCE_DIR}/./../../src/grpc/linux_install)
SET(PATH_SRC_PROTOBUF_FILES ${CMAKE_CURRENT_SOURCE_DIR}/./../../src/grpc/third_party/protobuf)
MESSAGE(STATUS "path test files: ${PATH_TEST_FILES}")

SET(PATH_OPENCV /opt/opencv3.4.2)
IF(EXISTS ${PATH_OPENCV})
	MESSAGE(STATUS "Found OpenCV: ${PATH_OPENCV}")
ELSE()
	MESSAGE(FATAL_ERROR "Can not find OpenCV in ${PATH_OPENCV}")
ENDIF()

# head file search path
INCLUDE_DIRECTORIES(
	${PATH_TEST_FILES}
	${PATH_OPENCV}/include
	${PATH_SRC_PROTOBUF_FILES}/src
	${PATH_SRC_GRPC_FILES}/include
)

# find opencv library
FIND_LIBRARY(opencv_core NAMES opencv_core PATHS ${PATH_OPENCV}/lib NO_DEFAULT_PATH)
FIND_LIBRARY(opencv_imgproc NAMES opencv_imgproc PATHS ${PATH_OPENCV}/lib NO_DEFAULT_PATH)
FIND_LIBRARY(opencv_highgui NAMES opencv_highgui PATHS ${PATH_OPENCV}/lib NO_DEFAULT_PATH)
FIND_LIBRARY(opencv_imgcodecs NAMES opencv_imgcodecs PATHS ${PATH_OPENCV}/lib NO_DEFAULT_PATH)
FIND_LIBRARY(opencv_video NAMES opencv_video PATHS ${PATH_OPENCV}/lib NO_DEFAULT_PATH)
FIND_LIBRARY(opencv_videoio NAMES opencv_videoio PATHS ${PATH_OPENCV}/lib NO_DEFAULT_PATH)
FIND_LIBRARY(opencv_objdetect NAMES opencv_objdetect PATHS ${PATH_OPENCV}/lib NO_DEFAULT_PATH)
FIND_LIBRARY(opencv_ml NAMES opencv_ml PATHS ${PATH_OPENCV}/lib NO_DEFAULT_PATH)
MESSAGE(STATUS "opencv libraries: ${opencv_core} ${opencv_imgproc} ${opencv_highgui} ${opencv_imgcodecs} ${opencv_video} ${opencv_videoio} ${opencv_objdetect} ${opencv_ml}")

# find dep library
SET(DEP_LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/build CACHE PATH "dep library path")
MESSAGE(STATUS "dep library dir: ${DEP_LIB_DIR}")
LINK_DIRECTORIES(${DEP_LIB_DIR})

# recursive query match files :*.cpp, *.cc, *.c
FILE(GLOB_RECURSE TEST_CPP_LIST ${PATH_TEST_FILES}/*.cpp)
FILE(GLOB_RECURSE TEST_CC_LIST ${PATH_TEST_FILES}/*.cc)
MESSAGE(STATUS "test files list: ${TEST_CPP_LIST} ${TEST_CC_LIST}")

# build executable program
ADD_EXECUTABLE(gRPC_Test ${TEST_CPP_LIST} ${TEST_CC_LIST})
# add dependent library: static and dynamic
TARGET_LINK_LIBRARIES(gRPC_Test
	${DEP_LIB_DIR}/libgrpc++_reflection.a
	${DEP_LIB_DIR}/libgrpc++.a
	${DEP_LIB_DIR}/libaddress_sorting.a
	${DEP_LIB_DIR}/libgrpc++_error_details.a
	${DEP_LIB_DIR}/libgrpc++_unsecure.a
	${DEP_LIB_DIR}/libgrpc.a
	${DEP_LIB_DIR}/libgrpc_unsecure.a
	${DEP_LIB_DIR}/libgpr.a
	${DEP_LIB_DIR}/libgrpc_cronet.a
	${DEP_LIB_DIR}/libgrpcpp_channelz.a
	${DEP_LIB_DIR}/libprotobuf.a
	${opencv_ml}
	${opencv_core}
	${opencv_imgproc}
	${opencv_highgui}
	${opencv_imgcodecs}
	${opencv_video}
	${opencv_videoio}
	${opencv_objdetect}
	z
	pthread
)

