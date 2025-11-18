add_executable(run_grpc_tests
    test_db.cpp
    test_client.cpp
    test_server.cpp
    ${TEST_PROTO_DIR}/test.pb.cc
    ${TEST_PROTO_DIR}/test.grpc.pb.cc
)

target_link_libraries(run_grpc_tests
    PRIVATE
    ${PROTOBUF_LIBRARIES}
    GTest::GTest
    GTest::Main
    pthread
    msa
    gRPC::grpc++
    gRPC::grpc++_reflection
)

add_test(NAME run_grpc_tests COMMAND run_grpc_tests)