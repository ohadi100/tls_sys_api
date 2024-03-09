
add_library(EngineCommon OBJECT
       ${CMAKE_CURRENT_SOURCE_DIR}/engineCommon.cpp
       ${CMAKE_CURRENT_SOURCE_DIR}/Globals.cpp
       ${CMAKE_CURRENT_SOURCE_DIR}/Logger.cpp
)

target_include_directories(EngineCommon PUBLIC
        "$<BUILD_INTERFACE:${INCLUDE_FILES}>"
        "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>")

target_link_libraries(EngineCommon
        PRIVATE
        sysapi_log::sysapi_log

        PUBLIC
        fnd_log::fnd_log
)

foreach (ENGINE ${ENGINE_TYPES})
        # Install the library
        install(TARGETS EngineCommon
                EXPORT tls_${ENGINE}Targets
                LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
endforeach (ENGINE)