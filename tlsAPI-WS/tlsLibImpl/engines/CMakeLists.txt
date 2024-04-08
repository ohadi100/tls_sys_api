set(wolfssl_SRC
        ${CMAKE_CURRENT_SOURCE_DIR}/wolfssl/PSK/WolfSSLPSKEngine.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/wolfssl/Cert/WolfSSLCertEngine.cpp
)

foreach (ENGINE ${ENGINE_TYPES})
        string(TOUPPER ${ENGINE} ENGINE_CAPITAL)

        add_library(engine${ENGINE} OBJECT
                ${TLS_LIB_SRC}/engines/TLSCertEngine.cpp
                ${TLS_LIB_SRC}/engines/TLSEngine.cpp
                ${${ENGINE}_SRC}
        )

        target_include_directories(engine${ENGINE} PUBLIC
                "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
                "$<BUILD_INTERFACE:${TLS_INCLUDES_${ENGINE}}>"
                "$<BUILD_INTERFACE:${INCLUDE_FILES}>"
                "$<BUILD_INTERFACE:${TLS_LIB_SRC}/ext/mocktee/APIs>"
                "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
        )

        target_link_libraries(engine${ENGINE}
                PRIVATE
                vwos-wolfssl::vwos-wolfssl
                EngineCommon

                PUBLIC
                ${AMSR_COMPONENTS}
        )

        target_compile_definitions(engine${ENGINE} 
                PRIVATE 
                TLS_ENGINE_${ENGINE_CAPITAL} 
                ${C_FLAGS_FOR_WOLFSSL_X509}
        )

endforeach (ENGINE)

