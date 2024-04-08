set(TEE_SOURCES
        src/ClientCertInitializerAPI.cpp
        src/TrustStoreUpdateAPI.cpp
        src/TLSTEEAPI.cpp
        src/MockTEEVKMSImpl.cpp
        src/MockTEEClientCertImpl.cpp
        src/MockTEETrustStoreImpl.cpp
        src/TLSTEEInterfaceClass.cpp
        src/ClientCertTEEInterfaceClass.cpp
        src/TrustStoreUpdateTEEInterfaceClass.cpp
        src/VKMSOnlineUpdateAPI.cpp
        src/VKMSOnlineUpdateInterfaceClass.cpp
        )

# workaround for alot of errors - will be treated as warning
# todo: remove this and address the errors
set_source_files_properties(${TEE_SOURCES} PROPERTIES COMPILE_FLAGS -Wno-error)

set(TEE_INCLUDES
        ${CMAKE_CURRENT_SOURCE_DIR}/../DevTools/include
        ${CMAKE_CURRENT_SOURCE_DIR}/../APIs
        ${CMAKE_CURRENT_SOURCE_DIR}/privateAPIs
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${THIRD_PARTY_SRC}/install/include/botan-2
)

add_library(MockTeeLib
        ${TEE_SOURCES}
)

target_include_directories(MockTeeLib PRIVATE
        "$<BUILD_INTERFACE:${TEE_INCLUDES}>"
        "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>")

target_compile_options(MockTeeLib 
        PRIVATE 
        -Wunused-parameter
)

target_link_libraries(MockTeeLib 
        PUBLIC
        botan_project
)