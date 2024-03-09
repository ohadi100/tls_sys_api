#[==[
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
# ]==]

#[=======================================================================[.rst:
Findsysapi_log
-----------------

Finds the sysapi_log library

Imported Targets
^^^^^^^^^^^^^^^^

This module provides the following imported targets, if found:

``sysapi_log::sysapi_log``
  The sysapi_log library

Result Variables
^^^^^^^^^^^^^^^^

This will define the following variables:

``sysapi_log_FOUND``
  True if the system has the sysapi_log library.
``sysapi_log_INCLUDE_DIRS``
  Include directories needed to use sysapi_log.
``sysapi_log_LIBRARIES``
  Libraries needed to link to sysapi_log.

Cache Variables
^^^^^^^^^^^^^^^

The following cache variables may also be set, if their respetive search succeeds:

``sysapi_log_INCLUDE_DIR``
  The directory containing ``ara/log/``.
``sysapi_log_LIBRARY``
  The path to the sysapi_log library.

#]=======================================================================]

message(WARNING "sysapi_log NOT FOUND. Find sysapi_log manually.")

find_path(sysapi_log_INCLUDE_DIR
    NAMES "ara/log/"
)

find_library(sysapi_log_LIBRARY 
    NAMES sysapi_log
    PATH_SUFFIXES sysapi
)

include(FindPackageHandleStandardArgs)

find_package_handle_standard_args(sysapi_log
  FOUND_VAR sysapi_log_FOUND
  REQUIRED_VARS
    sysapi_log_LIBRARY
    sysapi_log_INCLUDE_DIR
)

if(sysapi_log_FOUND AND NOT TARGET sysapi_log::sysapi_log)
    add_library(sysapi_log::sysapi_log SHARED IMPORTED)
    set_target_properties(sysapi_log::sysapi_log PROPERTIES
        IMPORTED_LOCATION "${sysapi_log_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${sysapi_log_INCLUDE_DIR}"
    )
endif()

mark_as_advanced(
    sysapi_log_INCLUDE_DIR
    sysapi_log_LIBRARY
)
