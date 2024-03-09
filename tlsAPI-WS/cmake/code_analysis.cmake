# @brief cmake static code analysis
 #
 # @file  src/cmake/code_analysis.cmake
 #
 # (c) 2022, 2023 CARIAD SE, All rights reserved.
 #
 # NOTICE:
 #
 # All the information and materials contained herein, including the
 # intellectual and technical concepts, are the property of CARIAD SE and may
 # be covered by patents, patents in process, and are protected by trade
 # secret and/or copyright law.
 #
 # The copyright notice above does not evidence any actual or intended
 # publication or disclosure of this source code, which includes information
 # and materials that are confidential and/or proprietary and trade secrets of
 # CARIAD SE.
 #
 # Any reproduction, dissemination, modification, distribution, public
 # performance, public display of or any other use of this source code and/or
 # any other information and/or material contained herein without the prior
 # written consent of CARIAD SE is strictly prohibited and in violation of
 # applicable laws.
 #
 # The receipt or possession of this source code and/or related information
 # does not convey or imply any rights to reproduce, disclose or distribute
 # its contents or to manufacture, use or sell anything that it may describe
 # in whole or in part.


 # disabled:
 #	llvm-header-guard: suggests head guards to start from root dir e.g. _HOME_DIR_..._SRC
 #	modernize-use-trailing-return-type: annotes every function not using auto + trailing return type. only usefull for templates?
 #	hicpp-vararg: cppcoreguidelines-pro-type-vararg does the same.
 #	readability-named-parameter: minor readability issue, personal choice to disable it
 #	cppcoreguidelines-pro-type-union: alternative is to use boost variant -> extra dependecy -> so do not care
 #	fuchsia-default-arguments-calls: will even complain about using std::string and not providing std::allocator.
 set(CLANG_TIDY_DISABLED_CHECKS
         llvmlibc-*
         llvm-include-order
         llvm-header-guard
         llvm-namespace-comment
         modernize-use-trailing-return-type
         readability-named-parameter
         hicpp-vararg
         cppcoreguidelines-pro-type-union-access
         fuchsia-default-arguments-calls
         readability-identifier-length
         readability-redundant-access-specifiers
         cppcoreguidelines-avoid-non-const-global-variables
         fuchsia-statically-constructed-objects
         fuchsia-overloaded-operator
         fuchsia-default-arguments
         google-runtime-references
         altera-*
         )

 set(CMAKE_CXX_FLAGS_SCA "-O3 -DNDEBUG -Wall -Wextra -Wpedantic -Wunused -Wshadow -Wconversion -Wpointer-arith -Wcast-qual -Wold-style-cast -Weffc++")
 #set(CMAKE_CXX_FLAGS_SCA "-O3 -Wall -Wextra -Wpedantic -Wunused -Wshadow -Wconversion -Wpointer-arith -Wcast-qual -Wold-style-cast -Weffc++")

 if(ENABLE_SCA)
    find_program(CLANG_TIDY_BIN clang-tidy)
     if(CLANG_TIDY_BIN)
         message(STATUS "clang-tidy found: ${CLANG_TIDY}")
         # set "*" as first list element to add later easily ",-" between all disabled checks when joining the list
         set(DISABLED_CHECKS "*" ${CLANG_TIDY_DISABLED_CHECKS})
         list(APPEND DISABLED_CHECKS ${CLANG_TIDY_DISABLE})
         list(JOIN DISABLED_CHECKS ",-" LIST_OF_DISABLED_CHECKS)
         set(CMAKE_CXX_CLANG_TIDY 
                ${CLANG_TIDY_BIN}
                -checks=${LIST_OF_DISABLED_CHECKS}
                --header-filter=.*
                --extra-arg=-std=c++14)
     else()
         message(AUTHOR_WARNING "clang-tidy not found")
     endif()

     find_program(CPPCHECK_BIN NAMES "cppcheck" DOC "cppcheck location")
     if(CPPCHECK_BIN)
         message(STATUS "cppcheck found: ${CPPCHECK_BIN}")
         set(CMAKE_CXX_CPPCHECK
                 ${CPPCHECK_BIN}
                 --enable=all
                 --suppress=missingInclude
                 --suppress=unmatchedSuppression
                 --suppress=unusedFunction
                 --suppress=noExplicitConstructor
                 -i=${CMAKE_SOURCE_DIR}/third_party
                 --inline-suppr
                 --inconclusive)
     else()
         message(AUTHOR_WARNING "cppcheck not found")
     endif()
 endif()

 # Asan
 set(CMAKE_C_FLAGS_ASAN
         "-fno-omit-frame-pointer -g -O0 -fsanitize=address,leak,undefined,float-divide-by-zero,float-cast-overflow,pointer-compare,pointer-subtract -fsanitize-address-use-after-scope -fsanitize-recover=all"
         CACHE STRING "C AddressSanitizer flags."
         FORCE)
 set(CMAKE_CXX_FLAGS_ASAN
         "-fno-omit-frame-pointer -g -O0 -fsanitize=address,leak,undefined,float-divide-by-zero,float-cast-overflow,pointer-compare,pointer-subtract -fsanitize-address-use-after-scope -fsanitize-recover=all"
         CACHE STRING "C++ AddressSanitizer flags."
         FORCE)

 # Tsan
 set(CMAKE_C_FLAGS_TSAN
         "-fno-omit-frame-pointer -g -O0 -fsanitize=thread"
         CACHE STRING "C ThreadSanitizer flags."
         FORCE)
 set(CMAKE_CXX_FLAGS_TSAN
         "-fno-omit-frame-pointer -g -O0 -fsanitize=thread"
         CACHE STRING "C++ ThreadSanitizer flags."
         FORCE)

 # --- SCA fine tuning ----

 # a function to set specific clang-tidy checks for a given target
 function(target_sca_clang_tidy)

     if(NOT CLANG_TIDY_BIN)
         message(STATUS "clang-tidy not found: ${CLANG_TIDY_BIN}")
         return()
     endif()

     set(prefix SCA_CLANG_TIDY)
     set(multiValues DISABLE)

     include(CMakeParseArguments)
     cmake_parse_arguments(${prefix} "${flags}" "${monoValues}" "${multiValues}" ${ARGN})

     message(TRACE "target_clang_tidy:unparsed: ${SCA_CLANG_TIDY_UNPARSED_ARGUMENTS}")
     message(TRACE "target_clang_tidy:disabled: ${SCA_CLANG_TIDY_DISABLE}")

     # "target" should equal ${SCA_CLANG_TIDY_UNPARSED_ARGUMENTS} -> there should be only 1 arg unparsed
     # TODO: ensure there is only 1 unparsed arg and that arg is an available target
     set(target "${SCA_CLANG_TIDY_UNPARSED_ARGUMENTS}")
     message(TRACE "target_clang_tidy:target: ${target}")

     list(JOIN SCA_CLANG_TIDY_DISABLE ",-" LIST_OF_DISABLED_CHECKS)

     get_target_property(OLD_CXX_CLANG_TIDY ${target} CXX_CLANG_TIDY)
     message(TRACE "target_clang_tidy:OLD_CXX_CLANG_TIDY=${OLD_CXX_CLANG_TIDY}")

     # replace the clang-tidy checks for the specific target
     # in detail: find the current checks using a regex and append the target specifc ones
     string(REGEX REPLACE "-checks=([^;]*)" "-checks=\\1,-${LIST_OF_DISABLED_CHECKS}" NEW_CXX_CLANG_TIDY "${OLD_CXX_CLANG_TIDY}")
     message(STATUS "target_clang_tidy:NEW_CXX_CLANG_TIDY=${NEW_CXX_CLANG_TIDY}")

     # set the new clang-tidy property for the target
     set_target_properties(${target} PROPERTIES CXX_CLANG_TIDY "${NEW_CXX_CLANG_TIDY}")
 endfunction()

 # a function to set specific clang-tidy checks for a project
 function(sca_clang_tidy)
     set(prefix SCA_CLANG_TIDY)
     set(multiValues DISABLE)

     include(CMakeParseArguments)
     cmake_parse_arguments(${prefix} "${flags}" "${monoValues}" "${multiValues}" ${ARGN})

     message(STATUS "sca_clang_tidy:unparsed: ${SCA_CLANG_TIDY_UNPARSED_ARGUMENTS}")
     message(STATUS "sca_clang_tidy:disabled: ${SCA_CLANG_TIDY_DISABLE}")

     # TODO: ensure there is no unparsed args

     set(LIST_OF_DISABLED_CHECKS "")
     list(JOIN SCA_CLANG_TIDY_DISABLE ",-" LIST_OF_DISABLED_CHECKS)

     set(OLD_CXX_CLANG_TIDY ${CMAKE_CXX_CLANG_TIDY})
     message(STATUS "sca_clang_tidy:OLD_CXX_CLANG_TIDY=${OLD_CXX_CLANG_TIDY}")

     # replace the clang-tidy checks for the specific target
     # in detail: find the current checks using a regex and append the target specifc ones
     string(REGEX REPLACE "-checks=([^;]*)" "-checks=\\1,-${LIST_OF_DISABLED_CHECKS}" NEW_CXX_CLANG_TIDY "${OLD_CXX_CLANG_TIDY}")
     message(STATUS "sca_clang_tidy:NEW_CXX_CLANG_TIDY=${NEW_CXX_CLANG_TIDY}")

     # set the new clang-tidy settings
     # TODO: set var in proper scope
     # alt: use project as target ?!? -> does not work
     # alt: iterate over all targets of a project and set it for each target separately
     #set(CMAKE_CXX_CLANG_TIDY "${NEW_CXX_CLANG_TIDY}" GLOBAL)
     #set_property(TARGET PROPERTY CXX_CLANG_TIDY "${NEW_CXX_CLANG_TIDY}")
     message(STATUS "sca_clang_tidy:CMAKE_CXX_CLANG_TIDY=${CMAKE_CXX_CLANG_TIDY} => ${PROJECT_NAME}")
 endfunction()

 # a function to set specific cppcheck warnings for a given target
 function(target_sca_cppcheck)

    if(NOT CPPCHECK_BIN)
        message(STATUS "cppcheck not found: ${CPPCHECK_BIN}")
        return()
    endif()

     set(prefix SCA_CPPCHECK)
     set(multiValues DISABLE)

     include(CMakeParseArguments)
     cmake_parse_arguments(${prefix} "${flags}" "${monoValues}" "${multiValues}" ${ARGN})

     message(TRACE "target_sca_cppcheck:unparsed: ${SCA_CPPCHECK_UNPARSED_ARGUMENTS}")
     message(TRACE "target_sca_cppcheck:disabled: ${SCA_CPPCHECK_DISABLE}")

     # "target" should equal ${SCA_CPPCHECK_UNPARSED_ARGUMENTS} -> there should be only 1 arg unparsed
     # TODO: ensure there is only 1 unparsed arg and that arg is an available target
     set(target "${SCA_CPPCHECK_UNPARSED_ARGUMENTS}")
     message(TRACE "target_sca_cppcheck:target: ${target}")

     list(TRANSFORM SCA_CPPCHECK_DISABLE PREPEND "--suppress=")

     get_target_property(OLD_CXX_CPPCHECK ${target} CXX_CPPCHECK)
     message(TRACE "target_sca_cppcheck:OLD_CXX_CPPCHECK=${OLD_CXX_CPPCHECK}")

     # replace the clang-tidy checks for the specific target
     # in detail: find the current checks using a regex and append the target specifc ones
     #string(REGEX REPLACE "--suppress=([^;]*)" "--suppress=${CMAKE_MATCH_0},${LIST_OF_DISABLED_CHECKS}" NEW_CXX_CPPCHECK "${OLD_CXX_CPPCHECK}")
     set(NEW_CXX_CPPCHECK "${OLD_CXX_CPPCHECK}" ${SCA_CPPCHECK_DISABLE})
     message(TRACE "target_sca_cppcheck:NEW_CXX_CPPCHECK=${NEW_CXX_CPPCHECK}")

     # set the new cppcheck property for the target
     set_target_properties(${target} PROPERTIES CXX_CPPCHECK "${NEW_CXX_CPPCHECK}")
 endfunction()