add_executable(run_thread_tests
    test_equeue.cpp
    test_pool.cpp
    ${TEST_PROTO_DIR}/test.pb.cc
    ${TEST_PROTO_DIR}/test.grpc.pb.cc
)

target_link_libraries(run_thread_tests
    PRIVATE
    ${PROTOBUF_LIBRARIES}
    GTest::GTest
    GTest::Main
    pthread
    gRPC::grpc++
    gRPC::grpc++_reflection
)

add_test(NAME run_thread_tests COMMAND run_thread_tests)