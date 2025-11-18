add_library(msa INTERFACE)

add_subdirectory(grpc)
add_subdirectory(cpu)
add_subdirectory(sync)

target_link_libraries(msa INTERFACE msa_grpc)
target_link_libraries(msa INTERFACE msa_cpu)
target_link_libraries(msa INTERFACE msa_sync)