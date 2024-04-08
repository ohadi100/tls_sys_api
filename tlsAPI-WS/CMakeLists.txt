cmake_minimum_required(VERSION 3.16)

set(VERSION 1.3.0r)
set(PROJECT_NAME ${CONAN_PKG_NAME})

project(${PROJECT_NAME}
  LANGUAGES CXX
  VERSION ${CONAN_PKG_VERSION}
)

message("Build tls version ${VERSION}")

# C++ standard
if(CMAKE_CXX_STANDARD)
	message(STATUS "Using CMAKE_CXX_STANDARD:C++${CMAKE_CXX_STANDARD}")
elseif(CMAKE_CXX_FLAGS MATCHES "-std=[^ ]+")
	set(CMAKE_CXX_STANDARD ${CMAKE_CXX_STANDARD_COMPUTED_DEFAULT})
	message(STATUS "Using C++ standard from CXXFLAGS via CMAKE_CXX_STANDARD_COMPUTED_DEFAULT:C++${CMAKE_CXX_STANDARD_COMPUTED_DEFAULT}")
else()
	set(CMAKE_CXX_STANDARD 14)
	message(STATUS "Using C++${CMAKE_CXX_STANDARD} since it is not explicitly set")
endif()

unset(WOLFSSL_LOGS_DIRECT_TO_SYSLOG CACHE)
option(WOLFSSL_LOGS_DIRECT_TO_SYSLOG "Direct WolfSSL into sys-log" OFF)
if (WOLFSSL_LOGS_DIRECT_TO_SYSLOG)
    add_definitions(-DWOLFSSL_LOGS_DIRECT_TO_SYSLOG)
    message(STATUS "Direct WolfSSL into sys-log: WOLFSSL_LOGS_DIRECT_TO_SYSLOG")
endif ()

unset(LOGS_DIRECT_TO_SYSLOG CACHE)
option(LOGS_DIRECT_TO_SYSLOG "Direct logs into sys-log" OFF)
if (LOGS_DIRECT_TO_SYSLOG)
    add_definitions(-DLOGS_DIRECT_TO_SYSLOG)
    message(STATUS "Using com-fnd_log: LOGS_DIRECT_TO_SYSLOG")
endif ()


# Directories specifying a search path for CMake modules to be loaded and run by the include()
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -Wall -g -O0 -Wextra")

set(CMAKE_CXX_STANDARD 14)

# Output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Set location variables
set(TLS_LIB_API ${CMAKE_SOURCE_DIR}/tlsAPI/includes)
set(TLS_LIB_SRC ${CMAKE_SOURCE_DIR}/tlsLibImpl)
set(THIRD_PARTY ${CMAKE_CURRENT_SOURCE_DIR}/third_party)
set(DOC_OUT ${CMAKE_CURRENT_SOURCE_DIR}/doc)
set(THIRD_PARTY_SRC ${CMAKE_SOURCE_DIR}/third_party)
set(AUX_FILE ${CMAKE_SOURCE_DIR}/auxiliary_files)

# Temporary files containing the domains/keys mappings
configure_file(auxiliary_files/keys.tsv /tmp/MockTeeStorage/VKMS/keys.tsv COPYONLY)
configure_file(auxiliary_files/domains.tsv /tmp/MockTeeStorage/VKMS/domains.tsv COPYONLY)
configure_file(auxiliary_files/keys_DlcDownload.tsv /tmp/MockTeeStorage/VKMS/keys_DlcDownload.tsv COPYONLY)
configure_file(auxiliary_files/domains.tsv domains.tsv COPYONLY)
configure_file(auxiliary_files/keys.tsv keys.tsv COPYONLY)

set(ENABLE_UNIT_TESTS OFF CACHE BOOL "Enable/disable Unit Tests target")
set(ENABLE_PARASOFT_SCA OFF CACHE BOOL "Enable/disable Parasoft SCA")

option(ARCH_ARM_LINUX "Build for ConMod-EU-NAD (arm7-Linux)" OFF)
option(TEST_COVERAGE "Generate coverage report" OFF)
option(BUILD_DOC "Build documentation" OFF)
option(DROP_TLS "Support drop tls" ON)
option(ICAS3_NO_OCSP_HARD_FAIL "Discard the requesting of OCSP if stapling is missing as part of the Hard-Fail fallback mechanism" OFF)
option(OE3_SPECIAL "Skip failure verification for duplicated certificates after root CA, Special for OC3" OFF)

# if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang" OR NOT DEFINED CMAKE_CXX_COMPILER_ID)
#     message(STATUS "Clang BUILD NOT USING pthread.")
#     unset(PTHREAD_LIB)
# else ()
#     message(STATUS "gcc BUILD USING pthread.")
#     set(PTHREAD_LIB pthread)
# endif ()

include(vwos-clang-tidy)
vwos_clang_tidy_add_targets(CLANG_TIDY_HEADER_FILTER "${CMAKE_SOURCE_DIR}/(tlsLibImpl|test|tlsAPI)/*.hpp" CLANG_TIDY_SOURCE_FILTER "${CMAKE_SOURCE_DIR}/(tlsLibImpl|test|tlsAPI)/*.cpp")

file(GLOB_RECURSE SOURCES
  ${CMAKE_SOURCE_DIR}/tlsLibImpl/**.cpp
  ${CMAKE_SOURCE_DIR}/tlsLibImpl/**.hpp
  ${CMAKE_SOURCE_DIR}/test/**.cpp
  ${CMAKE_SOURCE_DIR}/test/**.hpp
  ${CMAKE_SOURCE_DIR}/tlsAPI/**.cpp
  ${CMAKE_SOURCE_DIR}/tlsAPI/**.hpp  
)
include(vwos-clang-format)
vwos_clang_format_add_targets(SOURCE_FILES ${SOURCES})

# actual projects
set(ENGINE_TYPES wolfssl)
set(ENGINE wolfssl)

# Use sysapi logging library
include(GNUInstallDirs) # Install directory variables

if(${CMAKE_SYSTEM_NAME} STREQUAL "Android")
    list(APPEND CMAKE_FIND_ROOT_PATH ${CMAKE_PREFIX_PATH})
endif()

# Find Dependecies
set(CMAKE_FIND_PACKAGE_PREFER_CONFIG True)

set(AMSR_COMPONENTS
    amsr::log_ara_logging
)

find_package(AMSR CONFIG REQUIRED
    COMPONENTS
      ${AMSR_COMPONENTS}
)

find_package(vwos-wolfssl REQUIRED)
find_package(Threads REQUIRED)

set(INCLUDE_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/tlsAPI/includes
    ${TLS_LIB_SRC}/common/include
    ${TLS_LIB_SRC}/engines/include
    ${TLS_LIB_SRC}/streams/include
    ${TLS_LIB_SRC}/streams/inetaddr/include
    ${TLS_LIB_SRC}/streams/InternIOStream/include
    ${TLS_LIB_SRC}/streams/UserIOStream/include
    ${TLS_LIB_SRC}/TLSSocket/TLSClientSocket/Cert/include
    ${TLS_LIB_SRC}/TLSSocket/TLSClientSocket/PSK/include
    ${TLS_LIB_SRC}/TLSSocket/TLSServerSocket/PSK/include
    ${TLS_LIB_SRC}/TLSSessionEndpoint/include
    ${TLS_LIB_SRC}/TLSSocketFactory/include
)


# Exetrnal Projects
set(PROJECT_BOTAN project_botan)

include(botan)


set(TLS_INCLUDES_wolfssl
    ${TLS_LIB_SRC}/engines/wolfssl/Cert/include
    ${TLS_LIB_SRC}/engines/wolfssl/PSK/include
    ${TLS_LIB_SRC}/engines/wolfssl/include
)

set(MOCK_INCLUDES_PATH ${CMAKE_CURRENT_SOURCE_DIR}/test/unit/mock)

# compile external project MockTee and add MockTEE Library
set(mockteepath ${CMAKE_CURRENT_SOURCE_DIR}/tlsLibImpl/ext/mocktee)
add_subdirectory(${mockteepath}/MockTee)
set(TLS_INCLUDES_mocktee ${mockteepath}/APIs)

if (DROP_TLS)
    add_definitions(-DTLSAPI_WITH_DROP_SUPPORT)
endif ()

if (ICAS3_NO_OCSP_HARD_FAIL)
    add_definitions(-DTLSAPI_ICAS3_TEST_STAPLING_HARDFAIL_NO_OCSP_FALLBACK)
endif ()

if (OE3_SPECIAL)
    add_definitions(-DTLSAPI_ENABLE_OE3_SPECIAL_CERT_HANLING)
endif ()

# Main library
add_library(${PROJECT_NAME} SHARED
    tlsLibImpl/TLSLibApi/TLSLibApi.cpp
)

set_target_properties(${PROJECT_NAME} PROPERTIES
    CXX_EXTENSIONS OFF
    CXX_STANDARD ${CMAKE_CXX_STANDARD}
    CXX_STANDARD_REQUIRED ON
)

target_include_directories(${PROJECT_NAME} PUBLIC
    "$<BUILD_INTERFACE:${INCLUDE_FILES}>"
    "$<BUILD_INTERFACE:${TLS_INCLUDES_mocktee}>"
    "$<BUILD_INTERFACE:${TLS_INCLUDES_${ENGINE}}>"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
)

target_link_libraries(${PROJECT_NAME}
    PRIVATE
    EngineCommon
    engine${ENGINE}
    streams
    TLSSessionEndpoint
    TLSSocket_${ENGINE}
    TLSSocketFactory  
    MockTeeLib
    vwos-wolfssl::vwos-wolfssl

    PUBLIC
    ${AMSR_COMPONENTS}
)

# Install the library
# TODO

install(TARGETS ${PROJECT_NAME}
    LIBRARY DESTINATION lib
)

install(FILES 
            ${CMAKE_CURRENT_SOURCE_DIR}/auxiliary_files/domains.tsv
            ${CMAKE_CURRENT_SOURCE_DIR}/auxiliary_files/keys_DlcDownload.tsv
            ${CMAKE_CURRENT_SOURCE_DIR}/auxiliary_files/keys.tsv
        DESTINATION aux
)

# parasoft tools adds executable target thus it also adds entries to compile_commands.json
# To avoid unnecessary clang-tidy or other tool checks on these entries parasoft option should be
# enabled only when running parasoft targets
if(ENABLE_PARASOFT_SCA)
    include(vwos-parasoft-cpptest)

    # Define Parasoft target
    vwos_parasoft_add_target(sca
        TARGETS
        tls_${ENGINE}
    )

    # Define what is to be done by Parasoft
    vwos_parasoft_add_job(sca
        JOB RUN_SCA
        EXCLUDE
        **/src-gen/**
        **/tests/**
        **/tlsLibImpl/ext/**
        **/test/**
    )
endif()

# Install the headers
install(DIRECTORY ${TLS_LIB_API}/
        DESTINATION include
)


# Install release notes
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/../version.md
        DESTINATION releasenotes
)

# install docs
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/doc/TLSStreamAndSocketAPI.pdf
        DESTINATION share/doc/sysapi/tls
)

add_subdirectory(tlsLibImpl)

if (BUILD_DOC)
    include(doxygen)
endif ()

### Test
if (TEST_COVERAGE)
    include(gcov)
endif ()

if (ENABLE_UNIT_TESTS)
    enable_testing()
    include(GoogleTest)
    add_subdirectory(test)
endif ()


# ------------------------- End of Generic CMake Variable Logging ------------------

if (CMAKE_VERBOSE_MAKEFILE)

    # if you are building in-source, this is the same as CMAKE_SOURCE_DIR, otherwise
    # this is the top level directory of your build tree
    MESSAGE(STATUS "CMAKE_BINARY_DIR:         " ${CMAKE_BINARY_DIR})

    # if you are building in-source, this is the same as CMAKE_CURRENT_SOURCE_DIR, otherwise this
    # is the directory where the compiled or generated files from the current CMakeLists.txt will go to
    MESSAGE(STATUS "CMAKE_CURRENT_BINARY_DIR: " ${CMAKE_CURRENT_BINARY_DIR})

    # this is the directory, from which cmake was started, i.e. the top level source directory
    MESSAGE(STATUS "CMAKE_SOURCE_DIR:         " ${CMAKE_SOURCE_DIR})

    # this is the directory where the currently processed CMakeLists.txt is located in
    MESSAGE(STATUS "CMAKE_CURRENT_SOURCE_DIR: " ${CMAKE_CURRENT_SOURCE_DIR})

    # contains the full path to the top level directory of your build tree
    MESSAGE(STATUS "PROJECT_BINARY_DIR: " ${PROJECT_BINARY_DIR})

    # contains the full path to the root of your project source directory,
    # i.e. to the nearest directory where CMakeLists.txt contains the PROJECT() command
    MESSAGE(STATUS "PROJECT_SOURCE_DIR: " ${PROJECT_SOURCE_DIR})

    # set this variable to specify a common place where CMake should put all executable files
    # (instead of CMAKE_CURRENT_BINARY_DIR)
    MESSAGE(STATUS "EXECUTABLE_OUTPUT_PATH: " ${EXECUTABLE_OUTPUT_PATH})

    # set this variable to specify a common place where CMake should put all libraries
    # (instead of CMAKE_CURRENT_BINARY_DIR)
    MESSAGE(STATUS "LIBRARY_OUTPUT_PATH:     " ${LIBRARY_OUTPUT_PATH})

    # tell CMake to search first in directories listed in CMAKE_MODULE_PATH
    # when you use FIND_PACKAGE() or INCLUDE()
    MESSAGE(STATUS "CMAKE_MODULE_PATH: " ${CMAKE_MODULE_PATH})

    # this is the complete path of the cmake which runs currently (e.g. /usr/local/bin/cmake)
    MESSAGE(STATUS "CMAKE_COMMAND: " ${CMAKE_COMMAND})

    # this is the CMake installation directory
    MESSAGE(STATUS "CMAKE_ROOT: " ${CMAKE_ROOT})

    # this is the filename including the complete path of the file where this variable is used.
    MESSAGE(STATUS "CMAKE_CURRENT_LIST_FILE: " ${CMAKE_CURRENT_LIST_FILE})

    # this is linenumber where the variable is used
    MESSAGE(STATUS "CMAKE_CURRENT_LIST_LINE: " ${CMAKE_CURRENT_LIST_LINE})

    # this is used when searching for include files e.g. using the FIND_PATH() command.
    MESSAGE(STATUS "CMAKE_INCLUDE_PATH: " ${CMAKE_INCLUDE_PATH})

    # this is used when searching for libraries e.g. using the FIND_LIBRARY() command.
    MESSAGE(STATUS "CMAKE_LIBRARY_PATH: " ${CMAKE_LIBRARY_PATH})

    # the complete system name, e.g. "Linux-2.4.22", "FreeBSD-5.4-RELEASE" or "Windows 5.1"
    MESSAGE(STATUS "CMAKE_SYSTEM: " ${CMAKE_SYSTEM})

    # the short system name, e.g. "Linux", "FreeBSD" or "Windows"
    MESSAGE(STATUS "CMAKE_SYSTEM_NAME: " ${CMAKE_SYSTEM_NAME})

    # only the version part of CMAKE_SYSTEM
    MESSAGE(STATUS "CMAKE_SYSTEM_VERSION: " ${CMAKE_SYSTEM_VERSION})

    # the processor name (e.g. "Intel(R) Pentium(R) M processor 2.00GHz")
    MESSAGE(STATUS "CMAKE_SYSTEM_PROCESSOR: " ${CMAKE_SYSTEM_PROCESSOR})

    # is TRUE on all UNIX-like OS's, including Apple OS X and CygWin
    MESSAGE(STATUS "UNIX: " ${UNIX})

    # is TRUE on Windows, including CygWin
    MESSAGE(STATUS "WIN32: " ${WIN32})

    # is TRUE on Apple OS X
    MESSAGE(STATUS "APPLE: " ${APPLE})

    # is TRUE when using the MinGW compiler in Windows
    MESSAGE(STATUS "MINGW: " ${MINGW})

    # is TRUE on Windows when using the CygWin version of cmake
    MESSAGE(STATUS "CYGWIN: " ${CYGWIN})

    # is TRUE on Windows when using a Borland compiler
    MESSAGE(STATUS "BORLAND: " ${BORLAND})

    # Microsoft compiler
    MESSAGE(STATUS "MSVC: " ${MSVC})
    MESSAGE(STATUS "MSVC_IDE: " ${MSVC_IDE})
    MESSAGE(STATUS "MSVC60: " ${MSVC60})
    MESSAGE(STATUS "MSVC70: " ${MSVC70})
    MESSAGE(STATUS "MSVC71: " ${MSVC71})
    MESSAGE(STATUS "MSVC80: " ${MSVC80})
    MESSAGE(STATUS "CMAKE_COMPILER_2005: " ${CMAKE_COMPILER_2005})


    # set this to true if you don't want to rebuild the object files if the rules have changed,
    # but not the actual source files or headers (e.g. if you changed the some compiler switches)
    MESSAGE(STATUS "CMAKE_SKIP_RULE_DEPENDENCY: " ${CMAKE_SKIP_RULE_DEPENDENCY})

    # since CMake 2.1 the install rule depends on all, i.e. everything will be built before installing.
    # If you don't like this, set this one to true.
    MESSAGE(STATUS "CMAKE_SKIP_INSTALL_ALL_DEPENDENCY: " ${CMAKE_SKIP_INSTALL_ALL_DEPENDENCY})

    # If set, runtime paths are not added when using shared libraries. Default it is set to OFF
    MESSAGE(STATUS "CMAKE_SKIP_RPATH: " ${CMAKE_SKIP_RPATH})

    # set this to true if you are using makefiles and want to see the full compile and link
    # commands instead of only the shortened ones
    MESSAGE(STATUS "CMAKE_VERBOSE_MAKEFILE: " ${CMAKE_VERBOSE_MAKEFILE})

    # this will cause CMake to not put in the rules that re-run CMake. This might be useful if
    # you want to use the generated build files on another machine.
    MESSAGE(STATUS "CMAKE_SUPPRESS_REGENERATION: " ${CMAKE_SUPPRESS_REGENERATION})


    # A simple way to get switches to the compiler is to use ADD_DEFINITIONS().
    # But there are also two variables exactly for this purpose:

    # the compiler flags for compiling C sources
    MESSAGE(STATUS "CMAKE_C_FLAGS: " ${CMAKE_C_FLAGS})

    # the compiler flags for compiling C++ sources
    MESSAGE(STATUS "CMAKE_CXX_FLAGS: " ${CMAKE_CXX_FLAGS})


    # Choose the type of build.  Example: SET(CMAKE_BUILD_TYPE Debug)
    MESSAGE(STATUS "CMAKE_BUILD_TYPE: " ${CMAKE_BUILD_TYPE})

    # if this is set to ON, then all libraries are built as shared libraries by default.
    MESSAGE(STATUS "BUILD_SHARED_LIBS: " ${BUILD_SHARED_LIBS})

    # the compiler used for C files
    MESSAGE(STATUS "CMAKE_C_COMPILER: " ${CMAKE_C_COMPILER})

    # the compiler used for C++ files
    MESSAGE(STATUS "CMAKE_CXX_COMPILER: " ${CMAKE_CXX_COMPILER})

    # if the compiler is a variant of gcc, this should be set to 1
    MESSAGE(STATUS "CMAKE_COMPILER_IS_GNUCC: " ${CMAKE_COMPILER_IS_GNUCC})

    # if the compiler is a variant of g++, this should be set to 1
    MESSAGE(STATUS "CMAKE_COMPILER_IS_GNUCXX : " ${CMAKE_COMPILER_IS_GNUCXX})

    # the tools for creating libraries
    MESSAGE(STATUS "CMAKE_AR: " ${CMAKE_AR})
    MESSAGE(STATUS "CMAKE_RANLIB: " ${CMAKE_RANLIB})

    #
    #MESSAGE( STATUS ": " ${} )

    MESSAGE(STATUS "Build type: " ${CMAKE_BUILD_TYPE})
    MESSAGE(STATUS "Library Type: " ${LIB_TYPE})
    MESSAGE(STATUS "Compiler flags:" ${CMAKE_CXX_COMPILE_FLAGS})
    MESSAGE(STATUS "Compiler cxx debug flags:" ${CMAKE_CXX_FLAGS_DEBUG})
    MESSAGE(STATUS "Compiler cxx release flags:" ${CMAKE_CXX_FLAGS_RELEASE})
    MESSAGE(STATUS "Compiler cxx min size flags:" ${CMAKE_CXX_FLAGS_MINSIZEREL})
    MESSAGE(STATUS "Compiler cxx flags:" ${CMAKE_CXX_FLAGS})
    MESSAGE(STATUS "+++++++++++++++ sysapi_tls BUILD OPTIONS ++++++++++++++++++")

    MESSAGE(STATUS "LOGS_DIRECT_TO_SYSLOG:" ${LOGS_DIRECT_TO_SYSLOG})
    MESSAGE(STATUS "ARCH_ARM_LINUX:" ${ARCH_ARM_LINUX})
    MESSAGE(STATUS "ENABLE_UNIT_TESTS:" ${ENABLE_UNIT_TESTS})
    MESSAGE(STATUS "TEST_COVERAGE:" ${TEST_COVERAGE})
    MESSAGE(STATUS "BUILD_DOC:" ${BUILD_DOC})
    MESSAGE(STATUS "DROP_TLS:" ${DROP_TLS})
    MESSAGE(STATUS "ICAS3_NO_OCSP_HARD_FAIL:" ${ICAS3_NO_OCSP_HARD_FAIL})
    MESSAGE(STATUS "OE3_SPECIAL:" ${OE3_SPECIAL})
    MESSAGE(STATUS "+++++++++++++++ END sysapi_tls BUILD OPTIONS END ++++++++++++++++++")

    MESSAGE(STATUS "SYSAPI_TLS_SRC:" ${SYSAPI_TLS_SRC})
    MESSAGE(STATUS "SYSAPI_TLS_BIN:" ${SYSAPI_TLS_BIN})
    MESSAGE(STATUS "SYSAPI_TLS_INSTAL:" ${SYSAPI_TLS_INSTAL})


    # ------------------------- End of Generic CMake Variable Logging ------------------
endif ()
