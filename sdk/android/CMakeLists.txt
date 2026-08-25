cmake_minimum_required(VERSION 3.22)
project(quicp_jni C)

if(NOT DEFINED QUICP_RUST_LIB)
    message(FATAL_ERROR "Set QUICP_RUST_LIB to the target ABI's libquicp.a")
endif()

add_library(quicp STATIC IMPORTED)
set_target_properties(quicp PROPERTIES IMPORTED_LOCATION "${QUICP_RUST_LIB}")

add_library(quicp_jni SHARED src/main/cpp/quicp_jni.c)
target_compile_options(quicp_jni PRIVATE -Wall -Wextra -Werror)
target_include_directories(quicp_jni PRIVATE ../../include)
target_link_libraries(quicp_jni PRIVATE quicp log android)
