include_directories(${INCLUDE_FILES})

foreach(ENGINE ${ENGINE_TYPES})
    # Sample client application using MockTEE
    add_executable(client_cert_mocktee_${ENGINE} src/client_cert_mocktee.cpp)
    target_link_libraries(client_cert_mocktee_${ENGINE} tls_${ENGINE})

    add_executable(client_cert_${ENGINE} src/client_cert.cpp)
    target_link_libraries(client_cert_${ENGINE} tls_${ENGINE})

    add_executable(client_psk_${ENGINE} src/client_psk.cpp)
    target_link_libraries(client_psk_${ENGINE} tls_${ENGINE})

    add_executable(alpn_psk_${ENGINE} src/client_cert_alpn.cpp)
    target_link_libraries(alpn_psk_${ENGINE} tls_${ENGINE})

    add_executable(client_psk_DEMO_${ENGINE} src/client_psk_DEMO.cpp src/WaitableQueue.cpp)
    target_link_libraries(client_psk_DEMO_${ENGINE} tls_${ENGINE} Threads::Threads)

    # Sample server applications
    add_executable(server_${ENGINE} src/server.cpp)
    target_link_libraries(server_${ENGINE} tls_${ENGINE} Threads::Threads)

    add_executable(server_DEMO_${ENGINE} src/server_DEMO.cpp src/WaitableQueue.cpp)
    target_link_libraries(server_DEMO_${ENGINE} tls_${ENGINE} Threads::Threads)

endforeach(ENGINE)

add_executable(server_cert_wolfssl src/wolfssl_cert_server.cpp)
target_link_libraries(server_cert_wolfssl tls_wolfssl vwos-wolfssl::vwos-wolfssl)
