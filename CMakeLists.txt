cmake_minimum_required(VERSION 3.25)
project(MC_Dissector C)

set(CMAKE_C_STANDARD 11)

file(GLOB SOURCES "./*.c")
file(GLOB HEADERS "./*.h")
file(GLOB PROTOCOL_JE_SOURCES "./protocol_je/*.c")
file(GLOB PROTOCOL_JE_HEADERS "./protocol_je/*.h")
file(GLOB PROTOCOL_BE_SOURCES "./protocol_be/*.c")
file(GLOB PROTOCOL_BE_HEADERS "./protocol_be/*.h")

include_directories(
        $ENV{WIRESHARK_DIR}
        $ENV{WIRESHARK_DIR}/include
        $ENV{WIRESHARK_BUILD_DIR}
        $ENV{GLIB_DIR}/include/glib-2.0
        $ENV{GLIB_DIR}/lib/glib-2.0/include
)
link_directories($ENV{WIRESHARK_DIR_LIB})

add_library(MC_Dissector SHARED ${SOURCES} ${HEADERS} ${PROTOCOL_JE_SOURCES} ${PROTOCOL_JE_HEADERS} ${PROTOCOL_BE_SOURCES} ${PROTOCOL_BE_HEADERS})
target_link_libraries(MC_Dissector $ENV{WIRESHARK_LIB})
target_link_libraries(MC_Dissector $ENV{WSUTIL_LIB})

