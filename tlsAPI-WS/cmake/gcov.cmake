SET(GCOVR_FOLDER ${CMAKE_SOURCE_DIR}/test/gcov)
file(MAKE_DIRECTORY ${CMAKE_SOURCE_DIR})

SET(GCOVR gcovr)

SET(GCC_COVERAGE_COMPILE_FLAGS "-fprofile-arcs -ftest-coverage")
if (DARWIN_M1_HOST)
        SET(GCC_COVERAGE_LINK_FLAGS "")
else ()
        SET(GCC_COVERAGE_LINK_FLAGS "-lgcov")
endif()
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${GCC_COVERAGE_COMPILE_FLAGS}")
SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_LINKER_FLAGS} ${GCC_COVERAGE_LINK_FLAGS}")

SET(OUTPUT_DIR ${GCOVR_FOLDER}/html_output)
file(MAKE_DIRECTORY ${OUTPUT_DIR})

SET(EXCLUDED_GCOVR
        -e ${CMAKE_SOURCE_DIR}/tlsLibImpl/ext
        -e ${CMAKE_SOURCE_DIR}/tlsLibImpl/common
        )

add_custom_command(OUTPUT _run_gcovr_parser
        POST_BUILD
        COMMAND ${GCOVR_FOLDER}/scripts/InstallGcovr.sh
        # The following command will generate the report HTML file
        COMMAND ${GCOVR} -b -r ${CMAKE_SOURCE_DIR}/tlsLibImpl ${EXCLUDED_GCOVR} --html-details -o ${OUTPUT_DIR}/index.html --object-dir=${CMAKE_BINARY_DIR}
        # The following command just print the report to terminal, for fast debugging
        COMMAND ${GCOVR} -b -r ${CMAKE_SOURCE_DIR}/tlsLibImpl ${EXCLUDED_GCOVR} --object-dir=${CMAKE_BINARY_DIR} 
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        COMMAND rm ${DOC_OUT}/${TARGET_NAME}_report* || true
        # The following command will generate the PDF report for better readability
        COMMAND python3 ${GCOVR_FOLDER}/scripts/weasyprint ${OUTPUT_DIR}/index.html ${DOC_OUT}/${TARGET_NAME}_report_`date +'%d.%m.%y'`_v${VERSION}.pdf)
add_custom_target (coverage DEPENDS _run_gcovr_parser)
