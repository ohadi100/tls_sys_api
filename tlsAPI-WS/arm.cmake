SET(CMAKE_SYSTEM_NAME Linux)
SET(CMAKE_SYSTEM_VERSION 1)
SET(CMAKE_SYSTEM_PROCESSOR arm)

SET(CROSS_COMPILE_TARGET arm-linux-gnueabi)
SET(CROSS_COMPILE_CPU armel)
SET(CROSS_COMPILE_TOOLS $ENV{TOOLCHAIN_PATH})
if(NOT CROSS_COMPILE_TOOLS)
    message(FATAL_ERROR "Toolchain path not provided!")
endif()
SET(CROSS_COMPILE_PREFIX ${CROSS_COMPILE_TOOLS}/bin/arm-linux-gnueabihf-)

SET(CMAKE_SYSROOT ${CROSS_COMPILE_TOOLS}/arm-linux-gnueabihf/sysroot)
SET(CMAKE_C_COMPILER ${CROSS_COMPILE_PREFIX}gcc)
SET(CMAKE_CXX_COMPILER ${CROSS_COMPILE_PREFIX}g++)

SET(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
SET(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
SET(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
SET(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)