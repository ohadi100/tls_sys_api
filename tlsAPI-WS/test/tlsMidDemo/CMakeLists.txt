cmake_minimum_required(VERSION 3.15...3.23)

set(PROJECT_NAME ${CONAN_PKG_NAME})

project(${PROJECT_NAME}
  LANGUAGES CXX
  VERSION ${CONAN_PKG_VERSION}
)

if (${MID_TLS_SERVER})
    set(LOG_CTX_ID "SRV")
    set(LOG_DESCRIPTION "TLS MID source demo app")
    set(EXECUTABLE_NAME tls_mid_server)
    set(TLS_LIB sysapi_tls::sysapi_tls)
    set(PROCESS_ARG server)
else ()
    set(LOG_CTX_ID "CLT")
    set(LOG_DESCRIPTION "TLS MID client demo app")
    set(EXECUTABLE_NAME tls_mid_client)
    set(TLS_LIB sysapi_tls::sysapi_tls)
    set(PROCESS_ARG client)
endif()

include(vector-generator)

set(AMSR_COMPONENTS
    amsr::applicationbase
    amsr::socal
    amsr::com_r20_11
    amsr::em_application_client
    amsr::log_ara_logging
    amsr::someipprotocol
    amsr::ipcbinding
)

find_package(AMSR CONFIG REQUIRED
    COMPONENTS
      ${AMSR_COMPONENTS}
)

find_package(sysapi_tls REQUIRED)
find_package(Threads REQUIRED)


add_executable(${EXECUTABLE_NAME}
    ${CMAKE_CURRENT_SOURCE_DIR}/tlsMidDemo.cpp
)

target_link_libraries(${EXECUTABLE_NAME} 
        PUBLIC 
        ${AMSR_COMPONENTS}
        ${TLS_LIB}
        dl # Add this line to explicitly link against libdl
)

configure_file(${PROJECT_SOURCE_DIR}/model/design/Application.arxml
    ${CMAKE_CURRENT_BINARY_DIR}/model/design/Application.arxml @ONLY)
configure_file(${PROJECT_SOURCE_DIR}/model/deployment/Default/MachineLogChannelMixin.arxml
    ${CMAKE_CURRENT_BINARY_DIR}/model/deployment/Default/MachineLogChannelMixin.arxml @ONLY)
configure_file(${PROJECT_SOURCE_DIR}/model/deployment/Default/MachineSoftwareClusterMixin.arxml
    ${CMAKE_CURRENT_BINARY_DIR}/model/deployment/Default/MachineSoftwareClusterMixin.arxml @ONLY)
configure_file(${PROJECT_SOURCE_DIR}/model/deployment/Default/Process.arxml
    ${CMAKE_CURRENT_BINARY_DIR}/model/deployment/Default/Process.arxml @ONLY)
configure_file(${PROJECT_SOURCE_DIR}/model/deployment/Default/ProcessLoggingConfiguration.arxml
    ${CMAKE_CURRENT_BINARY_DIR}/model/deployment/Default/ProcessLoggingConfiguration.arxml @ONLY)
configure_file(${PROJECT_SOURCE_DIR}/model/deployment/Default/ProcessToMachineMapping.arxml
    ${CMAKE_CURRENT_BINARY_DIR}/model/deployment/Default/ProcessToMachineMapping.arxml @ONLY)


set(SRCGEN ${CMAKE_CURRENT_BINARY_DIR}/src-gen)
set(GENROOT ${SRCGEN}/${EXECUTABLE_NAME})
set(DVACFG_CMAKE_CONFIGURE ON)
dvacfg_file_gen(${EXECUTABLE_NAME}
  INPUT
    "${vwos-mid-integration-model_INCLUDE_DIR}"
    "${CMAKE_CURRENT_BINARY_DIR}/model"
    
  OUTPUT
    "${GENROOT}/amsr_applicationbase.cmake"
    "${GENROOT}/amsr_logapi_config.cmake"
    "${GENROOT}/amsr_modelleddatatypes_api.cmake"
    "${GENROOT}/amsr_socal.cmake"
    "${GENROOT}/amsr_someipprotocol.cmake"
    "${GENROOT}/amsr_ipcbinding.cmake"
  GENERATOR
    DvACfg::amsr_applicationbase
    DvACfg::amsr_ipcbinding
    DvACfg::amsr_logapi_config
    DvACfg::amsr_modelleddatatypes_api
    DvACfg::amsr_socal
    DvACfg::amsr_someipprotocol
  DIRECTORY "${SRCGEN}"
)

install(TARGETS ${EXECUTABLE_NAME}
    RUNTIME DESTINATION mid_demo/${EXECUTABLE_NAME}/bin
)

install(
    DIRECTORY
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/model/design>
    DESTINATION model
)

install(
    DIRECTORY
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/model/deployment>
    DESTINATION model
)