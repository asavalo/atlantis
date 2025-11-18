#include "libmsa/grpc/db.h"
#include <bsoncxx/json.hpp>
#include <ctime>

DBContext::DBContext(const std::string& module_name, const std::string& test_name)
    : client(mongocxx::uri{"mongodb://localhost:27017"}), 
      db(client[module_name]), collection(db[test_name]) {}

mongocxx::collection& DBContext::get_collection() {
    return collection;
}

bsoncxx::document::value create_document(const google::protobuf::Message& data, const std::string& type) {
    std::string binary_data;
    data.SerializeToString(&binary_data);

    auto now = std::time(nullptr);
    char time_buffer[80];
    std::strftime(time_buffer, 80, "%Y-%m-%d_%H-%M-%S", std::localtime(&now));

    bsoncxx::builder::stream::document document{};

    bsoncxx::types::b_binary binary_data2{
        bsoncxx::binary_sub_type::k_binary,
        static_cast<std::uint32_t>(binary_data.size()),
        reinterpret_cast<const uint8_t*>(binary_data.data())
    };

    document << "class" << data.GetTypeName()
             << "type" << type
             << "datetime" << time_buffer
             << "protobuf_data" << binary_data2;

    return document.extract();
}

mongocxx::stdx::optional<mongocxx::result::insert_one> save_request(const google::protobuf::Message& request, DBContext& db_ctx) {
    auto doc = create_document(request, "request");
    return db_ctx.get_collection().insert_one(doc.view());
}

mongocxx::stdx::optional<mongocxx::result::insert_one> save_response(const google::protobuf::Message& response, DBContext& db_ctx) {
    auto doc = create_document(response, "response");
    return db_ctx.get_collection().insert_one(doc.view());
}

std::string query_id(const bsoncxx::oid& id, DBContext& db_ctx) {
    auto maybe_result = db_ctx.get_collection().find_one(bsoncxx::builder::stream::document{} << "_id" << id << bsoncxx::builder::stream::finalize);
    if (maybe_result) {
        auto protobuf_data = (*maybe_result)["protobuf_data"].get_binary();
        return std::string((const char*)protobuf_data.bytes, protobuf_data.size);
    }
    return "";
}

std::vector<bsoncxx::document::value> load_requests(DBContext& db_ctx) {
    std::vector<bsoncxx::document::value> results;
    auto cursor = db_ctx.get_collection().find(bsoncxx::builder::stream::document{} << "type" << "request" << bsoncxx::builder::stream::finalize);
    for (auto&& doc : cursor) {
        results.push_back(bsoncxx::document::value{doc});
    }
    return results;
}