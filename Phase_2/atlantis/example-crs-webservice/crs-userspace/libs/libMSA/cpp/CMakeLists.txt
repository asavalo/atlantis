cmake_minimum_required(VERSION 3.10)
project(libmsa)

set(CMAKE_PREFIX_PATH "$ENV{HOME}/grpc_install")

# Find required packages
find_package(Protobuf CONFIG REQUIRED)
find_package(gRPC CONFIG REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(MONGOCXX REQUIRED libmongocxx)

include_directories($ENV{HOME}/grpc_install/include)
include_directories(${MONGOCXX_INCLUDE_DIRS})

include_directories(libmsa PUBLIC include)

add_subdirectory(src/libmsa)
add_subdirectory(tests)