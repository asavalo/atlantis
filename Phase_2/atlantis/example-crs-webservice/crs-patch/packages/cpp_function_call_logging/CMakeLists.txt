cmake_minimum_required(VERSION 3.13)
project(FunctionCallLogger LANGUAGES CXX C)

include(ExternalProject)

# Find llvm-config
find_program(LLVM_CONFIG "llvm-config" HINTS "/usr/local/bin" "/usr/bin")
if(NOT LLVM_CONFIG)
  message(FATAL_ERROR "llvm-config not found -- ${LLVM_CONFIG}")
endif()

# Get LLVM version
execute_process(
    COMMAND ${LLVM_CONFIG} --version
    OUTPUT_VARIABLE LLVM_VERSION
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

# Extract the major version number
string(REGEX REPLACE "^([0-9]+)\\..*" "\\1" LLVM_VERSION_MAJOR ${LLVM_VERSION})
message(STATUS "Found LLVM version ${LLVM_VERSION} (major version ${LLVM_VERSION_MAJOR})")

# Get LLVM CXX flags
execute_process(
    COMMAND ${LLVM_CONFIG} --cxxflags
    OUTPUT_VARIABLE LLVM_CXX_FLAGS
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

# Get LLVM include directories
execute_process(
    COMMAND ${LLVM_CONFIG} --includedir
    OUTPUT_VARIABLE LLVM_INCLUDE_DIR
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

# Set CXX flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${LLVM_CXX_FLAGS}")

# Include directories
include_directories(${LLVM_INCLUDE_DIR})

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} \
-Wredundant-decls -Wcast-align -Wmissing-include-dirs -Wswitch-default \
-Wextra -Wall -Winvalid-pch -Wredundant-decls -Wformat=2 \
-Wmissing-format-attribute -Wformat-nonliteral -Werror -Wno-error=deprecated-declarations")

# Mark nodelete to work around unload bug in upstream LLVM 5.0+
set(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS} -Wl,-z,nodelete")

# Create the LLVM pass
add_library(FunctionCallLoggerPass MODULE compiler/Main.cpp compiler/Pass.cpp)

add_library(Logger STATIC runtime/logger.c)
add_library(LoggerShared SHARED runtime/logger.c)

configure_file("compiler/clang-wrapper.in" "clang-wrapper" @ONLY)
configure_file("compiler/clang-wrapper.in" "clang-wrapper++" @ONLY)

