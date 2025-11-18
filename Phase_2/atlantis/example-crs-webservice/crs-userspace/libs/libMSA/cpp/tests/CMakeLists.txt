project(libmsa_tests)

set(TEST_PROTO_DIR "${CMAKE_CURRENT_SOURCE_DIR}/proto")

find_package(GTest REQUIRED)

include_directories(${GTEST_INCLUDE_DIRS})
include_directories(${TEST_PROTO_DIR}) 

add_subdirectory(thread)
add_subdirectory(grpc)
add_subdirectory(cpu)

enable_testing()