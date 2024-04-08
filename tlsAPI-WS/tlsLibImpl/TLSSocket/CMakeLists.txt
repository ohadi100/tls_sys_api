
foreach(ENGINE ${ENGINE_TYPES})
        string(TOUPPER ${ENGINE} ENGINE_CAPITAL)

        add_library(TLSSocket_${ENGINE} OBJECT
                ${CMAKE_CURRENT_SOURCE_DIR}/TLSClientSocket/Cert/TLSClientCertImpl.cpp
                ${CMAKE_CURRENT_SOURCE_DIR}/TLSClientSocket/PSK/TLSClientSocketImpl.cpp
                ${CMAKE_CURRENT_SOURCE_DIR}/TLSServerSocket/PSK/TLSServerSocketImpl.cpp
        )

        target_include_directories(TLSSocket_${ENGINE} PUBLIC
                "$<BUILD_INTERFACE:${INCLUDE_FILES}>"
                "$<BUILD_INTERFACE:${TLS_INCLUDES_${ENGINE}}>"
                "$<BUILD_INTERFACE:${TLS_LIB_SRC}/ext/mocktee/APIs>"
                "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>")

        target_link_libraries(TLSSocket_${ENGINE}
                PRIVATE
                TLSSessionEndpoint
                vwos-wolfssl::vwos-wolfssl
                ${AMSR_COMPONENTS}
        )

        target_compile_definitions(TLSSocket_${ENGINE} 
                PUBLIC 
                TLS_ENGINE_${ENGINE_CAPITAL} 
                ${C_FLAGS_FOR_WOLFSSL_X509}
        )

endforeach(ENGINE)