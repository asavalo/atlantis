#include "gtest/gtest.h"
#include <bsoncxx/oid.hpp>
#include "libmsa/grpc/db.h"
#include "test.pb.h"

class DBContextTest : public ::testing::Test {
protected:
    void SetUp() override {
        db_ctx = new DBContext("unittest", "testdb");
        request.set_team_name("Team Atlanta");
    }

    void TearDown() override {
        delete db_ctx;
    }

    DBContext* db_ctx;
    userspace::TestRequest request;
};

TEST_F(DBContextTest, SaveRequestTest) {
    save_request(request, *db_ctx);
    auto requests = load_requests(*db_ctx);
    ASSERT_GT(requests.size(), 0); 
}

TEST_F(DBContextTest, QueryByIdTest) {
    auto result = save_response(request, *db_ctx);
    if (result) {
        bsoncxx::oid inserted_id = result->inserted_id().get_oid().value;
        std::string protobuf_data = query_id(inserted_id, *db_ctx);
        userspace::TestRequest queried_request;
        queried_request.ParseFromString(protobuf_data);

        ASSERT_EQ(queried_request.team_name(), "Team Atlanta");
    }
    else{
        ASSERT_TRUE(false);
    }
}

TEST_F(DBContextTest, LoadRequestsTest) {
    save_request(request, *db_ctx);
    auto requests = load_requests(*db_ctx);
    ASSERT_GT(requests.size(), 0); 
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    mongocxx::instance instance{};  // Initialize MongoDB driver
    return RUN_ALL_TESTS();
}