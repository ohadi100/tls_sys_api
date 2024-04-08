set(SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/gtest_main.cpp
        SystemCallMock.cpp
        InternIOStreamTest.cpp

        ${TLS_LIB_SRC}/streams/InternIOStream/InternIOStream.cpp
        ${TLS_LIB_SRC}/streams/inetaddr/InetAddressFactory.cpp
        ${TLS_LIB_SRC}/streams/inetaddr/IPInetAddressImpl.cpp
        )

set(GTEST_NAME "stream_gtest")

add_executable(${GTEST_NAME} ${SOURCES})

target_include_directories(${GTEST_NAME} PUBLIC
        ${TLS_LIB_SRC}/streams/include
        ${TLS_LIB_SRC}/streams/inetaddr/include
        ${TLS_LIB_SRC}/tlsAPI/includes
        )

target_link_libraries(${GTEST_NAME} gtest::gtest EngineCommon)
add_test(NAME ${GTEST_NAME} COMMAND ${GTEST_NAME})
install(TARGETS ${GTEST_NAME} DESTINATION bin)
