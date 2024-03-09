
add_library(TLSSessionEndpoint OBJECT
        ${CMAKE_CURRENT_SOURCE_DIR}/TLSSessionEndpointImpl.cpp       
)

target_include_directories(TLSSessionEndpoint 
        PUBLIC
        "$<BUILD_INTERFACE:${INCLUDE_FILES}>"
        "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
)