find_package(Doxygen)
if (DOXYGEN_FOUND)
    set(DOXYGEN_IN  ${CMAKE_SOURCE_DIR}/tlsAPI/doxygen/${TARGET_NAME}.doxyfile)
    set(DOXYGEN_FILE  ${CMAKE_BINARY_DIR}/doxyfile)
    set(DOXYGEN_DOC_OUT ${CMAKE_SOURCE_DIR}/tlsAPI/doc)
    set(DOC_OUT ${CMAKE_SOURCE_DIR}/doc)


    configure_file(${DOXYGEN_IN} ${DOXYGEN_FILE} @ONLY)
    message("Doxygen build started")

    # note the option ALL which allows to build the docs together with the application
    add_custom_target(doc_doxygen ALL
            COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYGEN_FILE}
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
            COMMENT "Generating API documentation with Doxygen"
            VERBATIM
            )

    add_custom_command(TARGET doc_doxygen
            POST_BUILD
            COMMAND "${CMAKE_MAKE_PROGRAM}"
            COMMENT	"Running LaTeX for Doxygen documentation in ${DOXYGEN_DOC_OUT}/latex..."
            WORKING_DIRECTORY "${DOXYGEN_DOC_OUT}/latex"
            VERBATIM
            )

    add_custom_command(TARGET doc_doxygen POST_BUILD
            COMMAND cp ${DOXYGEN_DOC_OUT}/latex/refman.pdf ${DOC_OUT}/${TARGET_NAME}.pdf
            VERBATIM
            )

else (DOXYGEN_FOUND)
    message("Doxygen need to be installed to generate the doxygen documentation")
endif (DOXYGEN_FOUND)