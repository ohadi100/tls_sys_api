include(ExternalProject)

### QNX BUILD	
set(IMPLICIT_LINK_LIBRARIES ${CMAKE_CXX_IMPLICIT_LINK_LIBRARIES})
list(TRANSFORM IMPLICIT_LINK_LIBRARIES PREPEND "-l")
string(REPLACE ";" " " IMPLICIT_LINK_LIBRARIES "${IMPLICIT_LINK_LIBRARIES}")
set(IMPLICIT_LINK_DIRECTORIES ${CMAKE_CXX_IMPLICIT_LINK_DIRECTORIES})
list(TRANSFORM IMPLICIT_LINK_DIRECTORIES PREPEND "-L")
string(REPLACE ";" " " IMPLICIT_LINK_DIRECTORIES "${IMPLICIT_LINK_DIRECTORIES}")
set(LDFLAGS "${IMPLICIT_LINK_LIBRARIES} ${IMPLICIT_LINK_DIRECTORIES} -lsocket")
set(BOTAN_BUILD_TARGET --os=linux --cpu=arm --os=qnx --cc=gcc --cc-bin=${CMAKE_C_COMPILER} --cc-abi-flags=-V${CMAKE_CXX_COMPILER_TARGET} --ldflags=${LDFLAGS} --disable-neon)

if (ANDROID_PLATFORM )
        set(BOTAN_BUILD_TARGET --os=android --cc=clang --cpu=arm64 --disable-armv8crypto)
 #       --cc-bin=arm64-linux-android30-clang++
 endif ()
 if (DARWIN_M1_HOST)
        ### MAC BUILD	
        set(BOTAN_BUILD_TARGET --os=darwin --cpu=arm64)
 endif ()

if(NOT EXISTS "${THIRD_PARTY_SRC}/install/lib/libbotan-2.so")
    # compile external project botan
    ExternalProject_Add(botan
        PREFIX              ${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/external
        URL                 ${THIRD_PARTY_SRC}/archives/botan-2.8.0.tar.gz
        PATCH_COMMAND patch -p1 < ${THIRD_PARTY_SRC}/archives/botan-closeNoReset.patch
        INSTALL_DIR         ${THIRD_PARTY_SRC}/install

        CONFIGURE_COMMAND
        ${CMAKE_COMMAND}    -E env
        ${EXTERNAL_PROJECT_TOOLS}
        <SOURCE_DIR>/configure.py
        ${BOTAN_BUILD_TARGET}
        --prefix=<INSTALL_DIR>
        ${EXTERNAL_PROJECT_CPU}
        BUILD_COMMAND ${MAKE}

        BUILD_BYPRODUCTS <INSTALL_DIR>/lib/libbotan-2.a
        )
endif()

add_library(${PROJECT_BOTAN} SHARED IMPORTED GLOBAL)
set_property(TARGET ${PROJECT_BOTAN} PROPERTY IMPORTED_LOCATION ${THIRD_PARTY_SRC}/install/lib/libbotan-2.a)
add_dependencies(${PROJECT_BOTAN} botan)
