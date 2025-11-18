cmake_minimum_required(VERSION 3.29)

project(BullseyePass VERSION 1.0.0 LANGUAGES C CXX ASM)
find_package(LLVM 18.1.8 CONFIG)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_BUILD_TYPE Debug)

if (LLVM_FOUND)
    message(STATUS "LLVM_VERSION_MAJOR: ${LLVM_VERSION_MAJOR}")
    message(STATUS "LLVM_VERSION_MINOR: ${LLVM_VERSION_MINOR}")
    message(STATUS "LLVM_VERSION_PATCH: ${LLVM_VERSION_PATCH}")
else()
    message(FATAL_ERROR "You haven't install LLVM !")
endif()


add_definitions(${LLVM_DEFINITIONS})
include_directories(SYSTEM ${LLVM_INCLUDE_DIRS})

if (NOT LLVM_ENABLE_RTTI)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti")
endif()

set(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS} -Wl,-z,nodelete")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17 -stdlib=libstdc++")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -std=c++17 -stdlib=libstdc++")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG}")

# Error if SVF_DIR is not set
if (NOT DEFINED ENV{SVF_DIR})
  message(FATAL_ERROR "Please set the SVF_DIR environment variable to the path of your SVF installation.")
endif()

include_directories($ENV{SVF_DIR}/svf/include)
include_directories($ENV{SVF_DIR}/svf-llvm/include)
include_directories($ENV{SVF_DIR}/Release-build/include)
include_directories($ENV{SVF_DIR}/z3.obj/include)

# Enable dynamic linking against libLLVM.so
set(LLVM_LINK_LLVM_DYLIB ON)
set(LLVM_DYLIB_COMPONENTS core support option)

add_library(BullseyePass MODULE BullseyePass.cc)

llvm_map_components_to_libnames(LLVM_LIBS core support option)
target_link_libraries(BullseyePass LLVM $ENV{SVF_DIR}/Release-build/lib/libSvfLLVM.a $ENV{SVF_DIR}/Release-build/lib/libSvfCore.a)
