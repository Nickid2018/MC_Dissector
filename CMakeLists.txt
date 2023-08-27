cmake_minimum_required(VERSION 3.25)
project(MC_Dissector C)

set(CMAKE_C_STANDARD 11)

option(MC_DISSECTOR_FUNCTION_FEATURE "Enable function feature" ON)

if (MC_DISSECTOR_FUNCTION_FEATURE)
    message(STATUS "Enable function feature")
    add_compile_definitions(MC_DISSECTOR_FUNCTION_FEATURE)
endif ()

file(GLOB SOURCES "./*.c")
file(GLOB HEADERS "./*.h")
file(GLOB PROTOCOL_JE_SOURCES "./protocol_je/*.c")
file(GLOB PROTOCOL_JE_HEADERS "./protocol_je/*.h")
file(GLOB PROTOCOL_BE_SOURCES "./protocol_be/*.c")
file(GLOB PROTOCOL_BE_HEADERS "./protocol_be/*.h")
file(GLOB PROTOCOL_SOURCES "./protocols/*.c")
file(GLOB PROTOCOL_HEADERS "./protocols/*.h")
file(GLOB LIBRARY_CJSON_SOURCES "./cJSON/cJSON*.c")
file(GLOB LIBRARY_CJSON_HEADERS "./cJSON/cJSON*.h")

set(GEN_RESOURCE_DIR "${CMAKE_CURRENT_BINARY_DIR}/resources")
file(MAKE_DIRECTORY ${GEN_RESOURCE_DIR})

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
        string(FIND ${LIB} "win64ws" IS_WIN64_WS)
        string(FIND ${LIB} "libgcrypt" IS_LIB_GCRYPT)
        string(FIND ${LIB} "vcpkg-export" IS_LIB_GLIB)
        if (NOT IS_WIN64_WS EQUAL -1 AND NOT IS_LIB_GLIB EQUAL -1)
            message(STATUS "Found glib: ${LIB}")
            include_directories(
                    ${LIB}/installed/x64-windows/include/glib-2.0
                    ${LIB}/installed/x64-windows/lib/glib-2.0/include
            )
            link_directories(${LIB}/installed/x64-windows/lib)
            link_libraries(glib-2.0)
        endif ()
        if (NOT IS_WIN64_WS EQUAL -1 AND NOT IS_LIB_GCRYPT EQUAL -1)
            message(STATUS "Found gcrypt: ${LIB}")
            include_directories(
                    ${LIB}/installed/x64-windows/include
            )
            link_directories(${LIB}/installed/x64-windows/lib)
            link_libraries(gcrypt-20)
        endif ()
    endforeach ()
else ()
    find_package(PkgConfig)
    pkg_check_modules(wireshark REQUIRED IMPORTED_TARGET wireshark)
    link_libraries(PkgConfig::wireshark)
    pkg_check_modules(glib REQUIRED IMPORTED_TARGET glib-2.0)
    link_libraries(PkgConfig::glib)
    pkg_check_modules(gcrypt REQUIRED IMPORTED_TARGET libgcrypt)
    link_libraries(PkgConfig::gcrypt)
endif ()

macro(invoke_py message)
    execute_process(COMMAND python3 ${ARGN} ERROR_VARIABLE GEN_ERROR OUTPUT_VARIABLE GEN_OUTPUT RESULT_VARIABLE GEN_RESULT)
    if (NOT GEN_RESULT EQUAL 0)
        message(STATUS "python3 not found or run failed, trying python")
        execute_process(COMMAND python ${ARGN} ERROR_VARIABLE GEN_ERROR OUTPUT_VARIABLE GEN_OUTPUT RESULT_VARIABLE GEN_RESULT)
    endif ()
    if (NOT GEN_RESULT EQUAL 0)
        message(FATAL_ERROR "Failed to ${message}:\n${GEN_ERROR}")
    else ()
        message(STATUS "${message}:\n${GEN_OUTPUT}")
    endif ()
endmacro(invoke_py)

invoke_py("Generate Java String Data"
        "${PROJECT_SOURCE_DIR}/string_gen.py" "${PROJECT_SOURCE_DIR}/strings/strings_je.json"
        "${GEN_RESOURCE_DIR}/strings_je.c" "${GEN_RESOURCE_DIR}/strings_je.h" "je")
invoke_py("Generate Protocol Data"
        "${PROJECT_SOURCE_DIR}/protocol_data_gen.py" "${PROJECT_SOURCE_DIR}/minecraft-data" "${GEN_RESOURCE_DIR}")
invoke_py("Generate Resources"
        "${PROJECT_SOURCE_DIR}/resources_gen.py" "${PROJECT_SOURCE_DIR}/resources" "${GEN_RESOURCE_DIR}")

file(GLOB GEN_RESOURCE_HEADERS "${GEN_RESOURCE_DIR}/*.h")
file(GLOB GEN_RESOURCE_SOURCES "${GEN_RESOURCE_DIR}/*.c")
include_directories(${GEN_RESOURCE_DIR})
include_directories(".")

add_library(MC_Dissector SHARED ${SOURCES} ${HEADERS}
        ${PROTOCOL_JE_SOURCES} ${PROTOCOL_JE_HEADERS}
        ${PROTOCOL_BE_SOURCES} ${PROTOCOL_BE_HEADERS}
        ${PROTOCOL_SOURCES} ${PROTOCOL_HEADERS}
        ${LIBRARY_CJSON_SOURCES} ${LIBRARY_CJSON_HEADERS}
        ${GEN_RESOURCE_HEADERS} ${GEN_RESOURCE_SOURCES})

install(TARGETS MC_Dissector)
set_target_properties(MC_Dissector PROPERTIES OUTPUT_NAME "mcdissector" PREFIX "")

