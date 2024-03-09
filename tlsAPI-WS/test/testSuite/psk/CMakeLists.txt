set(PSK_TEST psk_test_suite)

# if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
#     unset(PTHREAD_LIB)
# else()
#    set(PTHREAD_LIB pthread)
# endif()

include_directories(${INCLUDE_DIR})

foreach(ENGINE ${ENGINE_TYPES})
    # Main executable
    add_executable(${ENGINE}_${PSK_TEST} psk.cpp)
    target_link_libraries(${ENGINE}_${PSK_TEST} tls_${ENGINE} Threads::Threads)
endforeach(ENGINE)