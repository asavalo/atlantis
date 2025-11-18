add_executable(run_cpu_tests
    test_affinity.cpp
)

target_link_libraries(run_cpu_tests
    PRIVATE
    ${PROTOBUF_LIBRARIES}
    GTest::GTest
    GTest::Main
    pthread
    msa
    gRPC::grpc++
    gRPC::grpc++_reflection
)

add_test(NAME run_cpu_tests COMMAND run_cpu_tests)