# This file is part of SymCC.
#
# SymCC is free software: you can redistribute it and/or modify it under the
# terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version.
#
# SymCC is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# SymCC. If not, see <https://www.gnu.org/licenses/>.

cmake_minimum_required(VERSION 3.16)
project(SymCC)

set(LLVM_VERSION "" CACHE STRING "LLVM version to use. The corresponding LLVM dev package must be installed.")
set(SYMCC_RT_BACKEND "qsym" CACHE STRING "The symbolic backend to use. Please check symcc-rt to get a list of the available backends.")
option(TARGET_32BIT "Make the compiler work correctly with -m32" OFF)

# We need to build the runtime as an external project because CMake otherwise
# doesn't allow us to build it twice with different options (one 32-bit version
# and one 64-bit variant).
include(ExternalProject)

# Find llvm-config
find_program(LLVM_CONFIG "llvm-config" HINTS "/usr/local/bin" "/usr/bin")

if (NOT LLVM_CONFIG)
    message(FATAL_ERROR "llvm-config not found. Make sure LLVM is installed and llvm-config is in your PATH.")
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
-Wmissing-format-attribute -Wformat-nonliteral -Werror -Wno-error=deprecated-declarations \
-g -w")

# Mark nodelete to work around unload bug in upstream LLVM 5.0+
set(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS} -Wl,-z,nodelete")

# This is the compiler pass that we later load into clang or opt. If LLVM is
# built without RTTI we have to disable it for our library too, otherwise we'll
# get linker errors.
add_library(SymCC MODULE
  compiler/Symbolizer.cpp
  compiler/ShortCircuiting.cpp
  compiler/VectorSymbolizer.cpp
  compiler/Pass.cpp
  compiler/Runtime.cpp
  compiler/Main.cpp)

set_target_properties(SymCC PROPERTIES OUTPUT_NAME "symcc")
if (NOT LLVM_ENABLE_RTTI)
  set_target_properties(SymCC PROPERTIES COMPILE_FLAGS "-fno-rtti")
endif()

set_target_properties(SymCC PROPERTIES COMPILE_FLAGS "-w")

find_program(CLANG_BINARY "clang"
  HINTS ${LLVM_TOOLS_BINARY_DIR}
  DOC "The clang binary to use in the symcc wrapper script.")
find_program(CLANGPP_BINARY "clang++"
  HINTS ${LLVM_TOOLS_BINARY_DIR}
  DOC "The clang binary to use in the sym++ wrapper script.")
if (NOT CLANG_BINARY)
  message(FATAL_ERROR "Clang not found; please make sure that the version corresponding to your LLVM installation is available.")
endif()

if (${LLVM_VERSION_MAJOR} LESS 13)
  set(CLANG_LOAD_PASS "-Xclang -load -Xclang ")
else()
  set(CLANG_LOAD_PASS "-fpass-plugin=")
endif()

configure_file("compiler/symcc.in" "symcc" @ONLY)
configure_file("compiler/sym++.in" "sym++" @ONLY)
