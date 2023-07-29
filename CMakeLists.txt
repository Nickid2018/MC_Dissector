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
link_directories($ENV{GLIB_DIR}/lib)

set(GEN_RESOURCE_DIR "${CMAKE_CURRENT_BINARY_DIR}/resources")
file(MAKE_DIRECTORY ${GEN_RESOURCE_DIR})

# String data
execute_process(COMMAND python3 "${PROJECT_SOURCE_DIR}/string_gen.py" "${PROJECT_SOURCE_DIR}/strings/strings_je.json"
        "${GEN_RESOURCE_DIR}/strings_je.c" "${GEN_RESOURCE_DIR}/strings_je.h" "je"
        ERROR_VARIABLE GEN_ERROR OUTPUT_VARIABLE GEN_OUTPUT RESULT_VARIABLE GEN_RESULT)

message(STATUS "Generate Output ${GEN_OUTPUT}")
message(STATUS "Generate Error ${GEN_ERROR}")
message(STATUS "Generate Result ${GEN_RESULT}")

# Protocol version data
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

# Protocol data
file(GLOB PROTOCOL_JE_DATA_FILE "minecraft-data/data/pc/*")
file(GLOB PROTOCOL_BE_DATA_FILE "minecraft-data/data/bedrock/*")

set(PROTOCOL_SCHEMA_FILE ${GEN_RESOURCE_DIR}/protocolSchemas.h)
file(WRITE ${PROTOCOL_SCHEMA_FILE} "#pragma once\n")
file(APPEND ${PROTOCOL_SCHEMA_FILE} "extern const int JE_PROTOCOL_SIZE;\n")
file(APPEND ${PROTOCOL_SCHEMA_FILE} "extern const char *JE_PROTOCOLS[];\n")
file(APPEND ${PROTOCOL_SCHEMA_FILE} "extern const int BE_PROTOCOL_SIZE;\n")
file(APPEND ${PROTOCOL_SCHEMA_FILE} "extern const char *BE_PROTOCOLS[];\n")

set(PROTOCOL_SCHEMA_FILE ${GEN_RESOURCE_DIR}/protocolSchemas.c)
file(WRITE ${PROTOCOL_SCHEMA_FILE} "#include \"protocolSchemas.h\"\n")

file(APPEND ${PROTOCOL_SCHEMA_FILE} "const char *JE_PROTOCOLS[] = {\n")
foreach (INPUT_FILE ${PROTOCOL_JE_DATA_FILE})
    if (NOT EXISTS ${INPUT_FILE}/protocol.json)
        continue()
    endif ()
    file(READ ${INPUT_FILE}/protocol.json FILE_DATA HEX)
    list(APPEND JE_PROTOCOLS ${FILE_NAME})
    string(REGEX REPLACE "([0-9a-f][0-9a-f])" "\\\\x\\1" FILE_DATA ${FILE_DATA})
    get_filename_component(FILE_NAME ${INPUT_FILE} NAME)
    file(APPEND ${PROTOCOL_SCHEMA_FILE} "    \"${FILE_NAME}\", \"${FILE_DATA}\",\n")
    message(STATUS "Found protocol data for JE${FILE_NAME}")
endforeach ()
file(APPEND ${PROTOCOL_SCHEMA_FILE} "\n};\n")
list(LENGTH JE_PROTOCOLS JE_PROTOCOL_SIZE)
file(APPEND ${PROTOCOL_SCHEMA_FILE} "const int JE_PROTOCOL_SIZE = ${JE_PROTOCOL_SIZE};\n")

file(APPEND ${PROTOCOL_SCHEMA_FILE} "const char *BE_PROTOCOLS[] = {\n")
foreach (INPUT_FILE ${PROTOCOL_BE_DATA_FILE})
    if (NOT EXISTS ${INPUT_FILE}/protocol.json)
        continue()
    endif ()
    file(READ ${INPUT_FILE}/protocol.json FILE_DATA HEX)
    list(APPEND BE_PROTOCOLS ${FILE_NAME})
    string(REGEX REPLACE "([0-9a-f][0-9a-f])" "\\\\x\\1" FILE_DATA ${FILE_DATA})
    get_filename_component(FILE_NAME ${INPUT_FILE} NAME)
    file(APPEND ${PROTOCOL_SCHEMA_FILE} "    \"${FILE_NAME}\", \"${FILE_DATA}\",\n")
    message(STATUS "Found protocol data for BE${FILE_NAME}")
endforeach ()
file(APPEND ${PROTOCOL_SCHEMA_FILE} "\n};\n")
list(LENGTH BE_PROTOCOLS BE_PROTOCOL_SIZE)
file(APPEND ${PROTOCOL_SCHEMA_FILE} "const int BE_PROTOCOL_SIZE = ${BE_PROTOCOL_SIZE};\n")

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
target_link_libraries(MC_Dissector wireshark)
target_link_libraries(MC_Dissector wsutil)
target_link_libraries(MC_Dissector glib-2.0)

install(TARGETS MC_Dissector)
set_target_properties(MC_Dissector PROPERTIES OUTPUT_NAME "mcdissector" PREFIX "")

