
add_library(TLSSocketFactory OBJECT
        ${CMAKE_CURRENT_SOURCE_DIR}/TLSSocketFactoryImpl.cpp
)

target_include_directories(TLSSocketFactory PUBLIC
        "$<BUILD_INTERFACE:${INCLUDE_FILES}>"
        "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>")

target_link_libraries(TLSSocketFactory
        PRIVATE
        streams
        ${AMSR_COMPONENTS}
)

foreach (ENGINE ${ENGINE_TYPES})
    # Install the library
    install(TARGETS TLSSocketFactory
            EXPORT tls_${ENGINE}Targets
            LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
endforeach (ENGINE)