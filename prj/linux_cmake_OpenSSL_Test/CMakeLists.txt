PROJECT(OpenSSL_Test)
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

ADD_DEFINITIONS(-D_DEFAULT_SOURCE=1) # fix bss_dgram.c: error: 'const struct in6_addr' has no member named 's6_addr32'

MESSAGE(STATUS "cmake current source dir: ${CMAKE_CURRENT_SOURCE_DIR}")
SET(PATH_TEST_FILES ${CMAKE_CURRENT_SOURCE_DIR}/./../../demo/OpenSSL_Test)
SET(PATH_SRC_OPENSSL_FILES ${CMAKE_CURRENT_SOURCE_DIR}/./../../src/openssl/build/install/include)
SET(PATH_SRC_B64_FILES ${CMAKE_CURRENT_SOURCE_DIR}/./../../src)
SET(PATH_SRC_CPPCODEC_FILES ${CMAKE_CURRENT_SOURCE_DIR}/./../../src/cppcodec)
SET(PATH_SRC_CURL_FILES ${CMAKE_CURRENT_SOURCE_DIR}/./../../src/curl)
SET(PATH_SRC_HTTP_PARSER_FILES ${CMAKE_CURRENT_SOURCE_DIR}/./../../src)
SET(PATH_SRC_BEARSSL_FILES ${CMAKE_CURRENT_SOURCE_DIR}/./../../src/bearssl)
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
	${PATH_SRC_OPENSSL_FILES}
	${PATH_SRC_B64_FILES}
	${PATH_SRC_CPPCODEC_FILES}
	${PATH_SRC_HPPT_PARSER_FILES}
	${PATH_SRC_CURL_FILES}/include
	${PATH_SRC_CURL_FILES}/build
	${PATH_SRC_BEARSSL_FILES}/inc
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
SET(SRC_C_LIST )
LIST(APPEND SRC_C_LIST ${PATH_SRC_B64_FILES}/b64/decode.c)
LIST(APPEND SRC_C_LIST ${PATH_SRC_B64_FILES}/b64/encode.c)
LIST(APPEND SRC_C_LIST ${PATH_SRC_HTTP_PARSER_FILES}/http-parser/http_parser.c)
MESSAGE(STATUS "test cpp list: ${TEST_CPP_LIST} ${TEST_C_LIST} ${SRC_C_LIST}")

# build executable program
ADD_EXECUTABLE(OpenSSL_Test ${TEST_CPP_LIST} ${TEST_CC_LIST} ${SRC_C_LIST})
# add dependent library: static and dynamic
TARGET_LINK_LIBRARIES(OpenSSL_Test
	${DEP_LIB_DIR}/libcrypto.so.1.1
	${DEP_LIB_DIR}/libssl.so.1.1
	${DEP_LIB_DIR}/libcurl.so
	${DEP_LIB_DIR}/libbearssl.so
	${opencv_ml}
	${opencv_core}
	${opencv_imgproc}
	${opencv_highgui}
	${opencv_imgcodecs}
	${opencv_video}
	${opencv_videoio}
	${opencv_objdetect}
	pthread
)

