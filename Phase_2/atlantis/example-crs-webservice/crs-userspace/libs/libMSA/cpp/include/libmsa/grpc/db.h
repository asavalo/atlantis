#ifndef DBCONTEXT_H
#define DBCONTEXT_H

#include <mongocxx/client.hpp>
#include <mongocxx/instance.hpp>
#include <mongocxx/uri.hpp>
#include <mongocxx/database.hpp>
#include <mongocxx/collection.hpp>
#include <bsoncxx/builder/stream/document.hpp>
#include <google/protobuf/message.h>
#include <vector>

class DBContext {
public:
    DBContext(const std::string& module_name, const std::string& test_name);
    mongocxx::collection& get_collection();
private:
    mongocxx::client client;
    mongocxx::database db;
    mongocxx::collection collection;
};

// Function declarations
bsoncxx::document::value create_document(const google::protobuf::Message& data, const std::string& type);
mongocxx::stdx::optional<mongocxx::result::insert_one> save_request(const google::protobuf::Message& request, DBContext& db_ctx);
mongocxx::stdx::optional<mongocxx::result::insert_one> save_response(const google::protobuf::Message& response, DBContext& db_ctx);
std::string query_id(const bsoncxx::oid& id, DBContext& db_ctx);
std::vector<bsoncxx::document::value> load_requests(DBContext& db_ctx);

#endif // DBCONTEXT_H