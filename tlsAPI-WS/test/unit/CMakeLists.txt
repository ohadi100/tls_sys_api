find_package(GTest REQUIRED)

add_definitions(-DUNIT_TEST)
add_definitions(-DTLS_ENGINE_WOLFSSL)
add_subdirectory(streams)

set(TLS_SOURCES
        # src
        ${TLS_LIB_SRC}/TLSSocket/TLSClientSocket/PSK/TLSClientSocketImpl.cpp
        ${TLS_LIB_SRC}/TLSSessionEndpoint/TLSSessionEndpointImpl.cpp
        ${TLS_LIB_SRC}/engines/TLSEngine.cpp
        ${TLS_LIB_SRC}/common/Globals.cpp
        ${TLS_LIB_SRC}/common/Logger.cpp
        ${TLS_LIB_SRC}/TLSSocket/TLSClientSocket/Cert/TLSClientCertImpl.cpp
        ${TLS_LIB_SRC}/engines/TLSCertEngine.cpp
        ${TLS_LIB_SRC}/TLSSocket/TLSServerSocket/PSK/TLSServerSocketImpl.cpp
        ${TLS_LIB_SRC}/streams/InternIOStream/InternIOStream.cpp
        ${TLS_LIB_SRC}/streams/UserIOStream/UserIOStream.cpp
        ${TLS_LIB_SRC}/streams/inetaddr/InetAddressFactory.cpp
        ${TLS_LIB_SRC}/streams/inetaddr/IPInetAddressImpl.cpp
        ${TLS_LIB_SRC}/TLSSocketFactory/TLSSocketFactoryImpl.cpp
        ${TLS_LIB_SRC}/engines/wolfssl/PSK/WolfSSLPSKEngine.cpp
        ${TLS_LIB_SRC}/engines/wolfssl/Cert/WolfSSLCertEngine.cpp
        ${TLS_LIB_SRC}/TLSLibApi/TLSLibApi.cpp
	${TLS_LIB_SRC}/ext/mocktee/MockTee/src/TLSTEEAPI.cpp
        )

set(GTESTS_SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/gtest_main.cpp
        mock/HelperMock.cpp
        TLSSocket/TLSClientSocket/TLSClientSocketImplTest.cpp
        TLSSocket/TLSClientSocket/TLSClientCertImplTest.cpp
        TLSSocket/TLSServerSocket/TLSServerSocketImplTest.cpp
        TLSSessionEndpoint/TLSSessionEndpointImplTest.cpp
        tlsAPI/TLSResultTests.cpp
        engines/WolfSSLCertEngineTest.cpp
        engines/WolfSSLPSKEngineTest.cpp
        engines/WolfSSLMockCaller.cpp
        engines/EngineCommonMockCaller.cpp
        ${TLS_LIB_SRC}/common/Logger.cpp
        engines/TLSReturnCodeTest.cpp
        engines/WolfSSLCommonTest.cpp
        TLSSocketFactory/TLSSocketFactoryImplTest.cpp
        engines/TLSCertEngineTest.cpp
        engines/TLSEngineTest.cpp
        streams/UserIOStreamTest.cpp
        streams/InetAddressFactoryTests.cpp
)


set(GTEST_TARGET_NAME "${TARGET_NAME}_gtest")

add_executable(${GTEST_TARGET_NAME}
        ${GTESTS_SOURCES} 
        ${TLS_SOURCES}
)

target_include_directories(${GTEST_TARGET_NAME} PUBLIC
		${INCLUDE_FILES}
		${TLS_INCLUDES_wolfssl}
		${TLS_INCLUDES_mocktee}
		mock/
		engines/helpTest/
		)

target_link_libraries(${GTEST_TARGET_NAME} 
        PRIVATE
        Threads::Threads 
        vwos-wolfssl::vwos-wolfssl
        gtest::gtest
        ${AMSR_COMPONENTS}
)

target_compile_definitions(${GTEST_TARGET_NAME} PUBLIC ${C_FLAGS_FOR_WOLFSSL_X509})

add_custom_target(tests DEPENDS ${GTEST_TARGET_NAME})
add_test(NAME ${GTEST_TARGET_NAME} COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/scripts/gtest2pdf)
install(TARGETS ${GTEST_TARGET_NAME} DESTINATION bin)
