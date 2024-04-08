set(PSK_TEST psk_stream_test_suite)

include_directories(${INCLUDE_DIR})

foreach(ENGINE ${ENGINE_TYPES})
    # Main executable
    add_executable(${ENGINE}_${PSK_TEST} psk_test_thread.cpp)
    target_link_libraries(${ENGINE}_${PSK_TEST} tls_${ENGINE} Threads::Threads)
endforeach(ENGINE)