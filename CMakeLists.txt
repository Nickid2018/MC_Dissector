cmake_minimum_required(VERSION 3.25)
project(MC_Dissector C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_VISIBILITY_PRESET hidden)

add_compile_definitions(SYSTEM_NAME=${CMAKE_SYSTEM_NAME})
if (CMAKE_BUILD_TYPE MATCHES Debug)
    message(STATUS "Debug mode")
    add_compile_definitions(DEBUG)
endif ()

add_compile_definitions(WS_BUILD_DLL)

file(GLOB SOURCES "${PROJECT_SOURCE_DIR}/*.c")
file(GLOB HEADERS "${PROJECT_SOURCE_DIR}/*.h")
file(GLOB PROTOCOL_JE_SOURCES "${PROJECT_SOURCE_DIR}/protocol_je/*.c")
file(GLOB PROTOCOL_JE_HEADERS "${PROJECT_SOURCE_DIR}/protocol_je/*.h")
file(GLOB PROTOCOL_BE_SOURCES "${PROJECT_SOURCE_DIR}/protocol_be/*.c")
file(GLOB PROTOCOL_BE_HEADERS "${PROJECT_SOURCE_DIR}/protocol_be/*.h")
file(GLOB_RECURSE PROTOCOL_SOURCES "${PROJECT_SOURCE_DIR}/protocol/*.c")
file(GLOB_RECURSE PROTOCOL_HEADERS "${PROJECT_SOURCE_DIR}/protocol/*.h")
file(GLOB UTILS_SOURCES "${PROJECT_SOURCE_DIR}/utils/*.c")
file(GLOB UTILS_HEADERS "${PROJECT_SOURCE_DIR}/utils/*.h")
list(REMOVE_ITEM SOURCES "${PROJECT_SOURCE_DIR}/check_version.c")

list(APPEND FILES_TO_BUILD ${SOURCES} ${HEADERS})
list(APPEND FILES_TO_BUILD ${PROTOCOL_JE_SOURCES} ${PROTOCOL_JE_HEADERS})
list(APPEND FILES_TO_BUILD ${PROTOCOL_BE_SOURCES} ${PROTOCOL_BE_HEADERS})
list(APPEND FILES_TO_BUILD ${PROTOCOL_SOURCES} ${PROTOCOL_HEADERS})
list(APPEND FILES_TO_BUILD ${UTILS_SOURCES} ${UTILS_HEADERS})

set(WIRESHARK_DIR $ENV{WIRESHARK_DIR})
set(WIRESHARK_BUILD_DIR $ENV{WIRESHARK_BUILD_DIR})
set(WIRESHARK_LIB_DIR $ENV{WIRESHARK_LIB_DIR})
set(WIRESHARK_LIB_FILE_DIR $ENV{WIRESHARK_LIB_FILE_DIR})

if (DEFINED ENV{WIRESHARK_LIB_DIR})
    include_directories(
            ${WIRESHARK_DIR}
            ${WIRESHARK_DIR}/include
            ${WIRESHARK_BUILD_DIR}
    )
    link_directories(${WIRESHARK_LIB_FILE_DIR})
    link_libraries(wireshark)
    link_libraries(wsutil)
    file(GLOB WIRESHARK_DOWNLOAD_LIBS "${WIRESHARK_LIB_DIR}/**")
    foreach (LIB ${WIRESHARK_DOWNLOAD_LIBS})
        if (NOT IS_DIRECTORY ${LIB})
            continue()
        endif ()
        string(FIND ${LIB} "libgcrypt" IS_LIB_GCRYPT)
        string(FIND ${LIB} "vcpkg-export" IS_LIB_GLIB)
        if (NOT IS_LIB_GLIB EQUAL -1)
            message(STATUS "Found glib: ${LIB}")
            include_directories(
                    ${LIB}/installed/x64-windows/include/glib-2.0
                    ${LIB}/installed/x64-windows/lib/glib-2.0/include
            )
            link_directories(${LIB}/installed/x64-windows/lib)
            link_libraries(glib-2.0)
        endif ()
        if (NOT IS_LIB_GCRYPT EQUAL -1)
            message(STATUS "Found gcrypt: ${LIB}")
            include_directories(
                    ${LIB}/include
            )
            link_directories(${LIB}/lib)
            link_libraries(gcrypt-20)
        endif ()
    endforeach ()
    include(FetchContent)
    FetchContent_Declare(
            cJSON
            GIT_REPOSITORY https://github.com/DaveGamble/cJSON.git
            GIT_TAG v1.7.18
    )
    FetchContent_MakeAvailable(cJSON)
    include_directories(${cJSON_SOURCE_DIR})
    list(APPEND FILES_TO_BUILD ${cJSON_SOURCE_DIR}/cJSON.c ${cJSON_SOURCE_DIR}/cJSON.h)
else ()
    find_package(PkgConfig)
    pkg_check_modules(wireshark REQUIRED IMPORTED_TARGET wireshark)
    link_libraries(PkgConfig::wireshark)
    pkg_check_modules(glib REQUIRED IMPORTED_TARGET glib-2.0)
    link_libraries(PkgConfig::glib)
    pkg_check_modules(gcrypt REQUIRED IMPORTED_TARGET libgcrypt)
    link_libraries(PkgConfig::gcrypt)
    pkg_check_modules(cjson REQUIRED IMPORTED_TARGET libcjson)
    link_libraries(PkgConfig::cjson)
endif ()

include_directories(".")
add_library(MC_Dissector SHARED ${FILES_TO_BUILD})

if (DEFINED ENV{WIRESHARK_LIB_DIR})
    try_compile(
            result "${CMAKE_BINARY_DIR}"
            SOURCES "${PROJECT_SOURCE_DIR}/check_version.c"
            CMAKE_FLAGS
                "-DINCLUDE_DIRECTORIES=${WIRESHARK_BUILD_DIR}"
                "-DLINK_DIRECTORIES=${WIRESHARK_LIB_FILE_DIR}"
            LINK_LIBRARIES wireshark
            OUTPUT_VARIABLE COMPILE_OUTPUT
    )
else ()
    try_compile(
            result "${CMAKE_BINARY_DIR}"
            SOURCES "${PROJECT_SOURCE_DIR}/check_version.c"
            LINK_LIBRARIES PkgConfig::wireshark
            OUTPUT_VARIABLE COMPILE_OUTPUT
    )
endif ()
string(REGEX MATCHALL ": [0-9]+" VERSION_SHORT_LIST "${COMPILE_OUTPUT}")
foreach (VERSION_SHORT ${VERSION_SHORT_LIST})
    string(SUBSTRING ${VERSION_SHORT} 2 -1 VERSION_SHORT)
    list(APPEND VERSION_LIST ${VERSION_SHORT})
endforeach ()
list(GET VERSION_LIST 0 wireshark_VERSION_MAJOR)
list(GET VERSION_LIST 1 wireshark_VERSION_MINOR)
message(STATUS "WireShark version: ${wireshark_VERSION_MAJOR}.${wireshark_VERSION_MINOR}")

set_target_properties(MC_Dissector PROPERTIES OUTPUT_NAME "mcdissector" PREFIX "")
install(
        TARGETS MC_Dissector
        LIBRARY DESTINATION "wireshark/plugins/${wireshark_VERSION_MAJOR}.${wireshark_VERSION_MINOR}/epan"
        NAMELINK_SKIP
)