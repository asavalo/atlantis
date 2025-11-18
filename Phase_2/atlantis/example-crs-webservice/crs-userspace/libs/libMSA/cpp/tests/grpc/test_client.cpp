#include "gtest/gtest.h"
#include <thread>
#include <chrono>
#include "libmsa/grpc/client.h"
#include "test.pb.h"
#include "test.grpc.pb.h"

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

class TestClient : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        server_thread = std::thread([]() {
            grpc::ServerBuilder builder;
            TestServiceImpl service;
            builder.AddListeningPort("0.0.0.0:50051", grpc::InsecureServerCredentials());
            builder.RegisterService(&service);
            server = builder.BuildAndStart();

            server->Wait();
        });

        // Allow the server to start
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    static void TearDownTestSuite() {
        if (server != nullptr) {
            server->Shutdown();
            server_thread.join();
        }
    }

    static std::unique_ptr<grpc::Server> server;
    static std::thread server_thread;
};

std::unique_ptr<grpc::Server> TestClient::server;
std::thread TestClient::server_thread;

TEST_F(TestClient, TestClientNoIntercept) {
    auto channel = create_channel("localhost:50051", nullptr);
    auto stub = userspace::Test::NewStub(channel);

    userspace::TestRequest request;
    request.set_team_name(payload);
    userspace::TestResponse response;

    grpc::ClientContext context;
    grpc::Status status = stub->TestService(&context, request, &response);

    EXPECT_TRUE(status.ok());
    EXPECT_EQ(response.cnt(), cnt);

    stub.reset();
    channel.reset();
}

TEST_F(TestClient, TestClientWithIntercept) {
    DBContext db_ctx("unittest", "testclient");
    auto channel = create_channel("localhost:50051", &db_ctx);
    auto stub = userspace::Test::NewStub(channel);

    userspace::TestRequest request;
    request.set_team_name(payload);
    userspace::TestResponse response;

    grpc::ClientContext context;
    grpc::Status status = stub->TestService(&context, request, &response);

    EXPECT_TRUE(status.ok());
    EXPECT_EQ(response.cnt(), 1110);

    stub.reset();
    channel.reset();
}