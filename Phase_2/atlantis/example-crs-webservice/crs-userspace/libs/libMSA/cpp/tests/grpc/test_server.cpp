#include "gtest/gtest.h"
#include <thread>
#include <chrono>
#include "libmsa/grpc/server.h"
#include "test.pb.h"
#include "test.grpc.pb.h"

static int port = 50051;
static const char* payload = "Team-Atlanta";
static const int cnt = 1110;

class TestServiceImpl final : public userspace::Test::Service {
public:
    grpc::Status TestService(grpc::ServerContext* context, const userspace::TestRequest* request, userspace::TestResponse* response) override {
        EXPECT_EQ(request->team_name(), payload);
        response->set_cnt(cnt);
        return grpc::Status::OK;
    }
};

class TestServer : public ::testing::Test {
protected:
    void SetUp() {
        channel = grpc::CreateChannel("localhost:" + std::to_string(port), grpc::InsecureChannelCredentials());
        stub = userspace::Test::NewStub(channel);
    }

    void TearDown() {
        stub.reset();
        channel.reset();
    }

    void do_client() {
        userspace::TestRequest request;
        request.set_team_name(payload);
        userspace::TestResponse response;

        grpc::ClientContext context;
        grpc::Status status = stub->TestService(&context, request, &response);

        EXPECT_TRUE(status.ok());
        EXPECT_EQ(response.cnt(), cnt);
    }

    std::shared_ptr<grpc::Channel> channel;
    std::unique_ptr<userspace::Test::Stub> stub;
};

TEST_F(TestServer, TestServerNoIntercept) {
    TestServiceImpl service;
    auto server = open_port(port, &service, nullptr);
    
    do_client();

    std::this_thread::sleep_for(std::chrono::seconds(3));

    server->Shutdown();
}

TEST_F(TestServer, TestServerWithIntercept) {
    DBContext db_ctx("unittest", "testserver");
    TestServiceImpl service;
    auto server = open_port(port, &service, &db_ctx);
    
    do_client();

    std::this_thread::sleep_for(std::chrono::seconds(3));

    server->Shutdown();
}