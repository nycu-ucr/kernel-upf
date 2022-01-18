cmake_minimum_required(VERSION 3.5)

project(free5GC_UPF_main C)

# use, i.e. don't skip the full RPATH for the build tree
set(CMAKE_SKIP_BUILD_RPATH FALSE)

# when building, don't use the install RPATH already
# (but later on when installing)
set(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)

SET(CMAKE_VERBOSE_MAKEFILE ON)
SET(CMAKE_BUILD_WITH_INSTALL_RPATH ON)
if (APPLE)
    set(CMAKE_INSTALL_RPATH "@executable_path/../lib")
else()
    set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_RPATH}:$\{ORIGIN}\/../../build/utlt_logger"
                            "$\{ORIGIN}\/../../build/updk/src/third_party/libgtp5gnl/lib/"
                            )
endif()

set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

link_directories(${LOGGER_DST})

# Sources
file(GLOB SRC_FILES
    "*.c"
    "n4/*.c"
    "up/*.c"
)
add_executable(${PROJECT_NAME} ${SRC_FILES})
set_target_properties(
    ${PROJECT_NAME}
    PROPERTIES
        OUTPUT_NAME "${BUILD_BIN_DIR}/free5gc-upfd"
        SUFFIX ""
)

target_include_directories(${PROJECT_NAME} PRIVATE
    ${LOGGER_DST}
    "${CMAKE_SOURCE_DIR}/src"
    "${CMAKE_SOURCE_DIR}/lib/pfcp/include"
    "${CMAKE_SOURCE_DIR}/lib/utlt/include"
    "${CMAKE_SOURCE_DIR}/lib/utlt/logger/include"
    "${CMAKE_SOURCE_DIR}/updk/include"
)
target_link_libraries(${PROJECT_NAME} PRIVATE
    # TODO: "free5GC_updk_kernel" is hard code for using updk/src/kernel, it may be changed if use other repo
    free5GC_updk free5GC_updk_${UPDK_PKTPROC_MODULE} free5GC_utlt free5GC_pfcp logger yaml
)
#target_compile_options(${PROJECT_NAME} PRIVATE -Wall -Werror)

# PFCP Request and Response drop test
# Enable the following macro enable based on your drop test
#target_compile_definitions(${PROJECT_NAME} PRIVATE PFCP_REQUEST_DROP_COUNT=5)
#target_compile_definitions(${PROJECT_NAME} PRIVATE PFCP_REQUEST_DROP_TEST=1)
#target_compile_definitions(${PROJECT_NAME} PRIVATE PFCP_RESPONSE_DROP_COUNT=5)
#target_compile_definitions(${PROJECT_NAME} PRIVATE PFCP_RESPONSE_DROP_TEST=1)
