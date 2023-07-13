cmake_minimum_required(VERSION 3.25)
project(MC_Dissector C)

set(CMAKE_C_STANDARD 11)

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

include_directories(
        $ENV{WIRESHARK_DIR}
        $ENV{WIRESHARK_DIR}/include
        $ENV{WIRESHARK_BUILD_DIR}
        $ENV{GLIB_DIR}/include/glib-2.0
        $ENV{GLIB_DIR}/lib/glib-2.0/include
)
link_directories($ENV{WIRESHARK_DIR_LIB})

# Resources
set(GEN_RESOURCE_DIR "${CMAKE_CURRENT_BINARY_DIR}/resources")
file(GLOB GEN_RESOURCE_HEADERS "${GEN_RESOURCE_DIR}/*.h")
file(GLOB GEN_RESOURCE_SOURCES "${GEN_RESOURCE_DIR}/*.c")
file(MAKE_DIRECTORY ${GEN_RESOURCE_DIR})

file(GLOB PROTOCOL_VERSION_JE_DATA_FILE "minecraft-data/data/pc/common/protocolVersions.json")
file(GLOB PROTOCOL_VERSION_BE_DATA_FILE "minecraft-data/data/bedrock/common/protocolVersions.json")
set(PROTOCOL_VERSION_HEADER "${GEN_RESOURCE_DIR}/protocolVersions.h")
set(PROTOCOL_VERSION_SOURCE "${GEN_RESOURCE_DIR}/protocolVersions.c")

file(WRITE ${PROTOCOL_VERSION_HEADER} "#pragma once\n")
file(APPEND ${PROTOCOL_VERSION_HEADER} "extern const char* PROTOCOL_VERSIONS_JE;\n")
file(APPEND ${PROTOCOL_VERSION_HEADER} "extern const char* PROTOCOL_VERSIONS_BE;\n")

file(WRITE ${PROTOCOL_VERSION_SOURCE} "#include \"protocolVersions.h\"\n")
file(APPEND ${PROTOCOL_VERSION_SOURCE} "const char* PROTOCOL_VERSIONS_JE = \"")
file(READ ${PROTOCOL_VERSION_JE_DATA_FILE} FILE_DATA HEX)
string(REGEX REPLACE "([0-9a-f][0-9a-f])" "\\\\x\\1" FILE_DATA ${FILE_DATA})
file(APPEND ${PROTOCOL_VERSION_SOURCE} "${FILE_DATA}\";\n")
file(APPEND ${PROTOCOL_VERSION_SOURCE} "const char* PROTOCOL_VERSIONS_BE = \"")
file(READ ${PROTOCOL_VERSION_BE_DATA_FILE} FILE_DATA HEX)
string(REGEX REPLACE "([0-9a-f][0-9a-f])" "\\\\x\\1" FILE_DATA ${FILE_DATA})
file(APPEND ${PROTOCOL_VERSION_SOURCE} "${FILE_DATA}\";")

include_directories(${GEN_RESOURCE_DIR})

add_library(MC_Dissector SHARED ${SOURCES} ${HEADERS}
        ${PROTOCOL_JE_SOURCES} ${PROTOCOL_JE_HEADERS}
        ${PROTOCOL_BE_SOURCES} ${PROTOCOL_BE_HEADERS}
        ${PROTOCOL_SOURCES} ${PROTOCOL_HEADERS}
        ${LIBRARY_CJSON_SOURCES} ${LIBRARY_CJSON_HEADERS}
        ${GEN_RESOURCE_HEADERS} ${GEN_RESOURCE_SOURCES})
target_link_libraries(MC_Dissector $ENV{WIRESHARK_LIB})
target_link_libraries(MC_Dissector $ENV{WSUTIL_LIB})
target_link_libraries(MC_Dissector glib-2.0-0)

