add_library(msa_grpc STATIC db.cpp client.cpp server.cpp)

target_link_libraries(msa_grpc
    PRIVATE
    ${PROTOBUF_LIBRARIES}
    ${MONGOCXX_LIBRARIES}
    gRPC::grpc++
    gRPC::grpc++_reflection
)