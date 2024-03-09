set(TLS_API_WRAPPER tls_api_wrapper)

set(ENGINE_TYPES wolfssl)

foreach(ENGINE ${ENGINE_TYPES})
    # Main executable
    add_library(${ENGINE}_${TLS_API_WRAPPER} SHARED
            TLSLibApiCWrapper.cpp
            TLSLibApiWrapper.cpp
            TestIOStreamImpl.cpp
            TestTLSOcspHandler.cpp)

    target_link_libraries(${ENGINE}_${TLS_API_WRAPPER} tls_${ENGINE})
endforeach(ENGINE)