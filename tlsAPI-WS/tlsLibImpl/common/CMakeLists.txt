
add_library(EngineCommon OBJECT
       ${CMAKE_CURRENT_SOURCE_DIR}/engineCommon.cpp
)

target_include_directories(EngineCommon PUBLIC
        "$<BUILD_INTERFACE:${INCLUDE_FILES}>"
        "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>")

target_link_libraries(EngineCommon
        PUBLIC
        ${AMSR_COMPONENTS}
)

foreach (ENGINE ${ENGINE_TYPES})
        # Install the library
        install(TARGETS EngineCommon
                EXPORT tls_${ENGINE}Targets
                LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
endforeach (ENGINE)