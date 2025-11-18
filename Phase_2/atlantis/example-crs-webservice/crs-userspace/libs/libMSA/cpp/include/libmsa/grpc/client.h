#ifndef CLIENT_H
#define CLIENT_H

#include <grpcpp/grpcpp.h>
#include "db.h"

class DBSaveClientInterceptor : public grpc::experimental::Interceptor {
public:
    explicit DBSaveClientInterceptor(DBContext* db_ctx) : db_ctx_(db_ctx) {}

    void Intercept(grpc::experimental::InterceptorBatchMethods* methods) override;

private:
    DBContext* db_ctx_;
};

class DBSaveClientInterceptorFactory : public grpc::experimental::ClientInterceptorFactoryInterface {
public:
    explicit DBSaveClientInterceptorFactory(DBContext* db_ctx) : db_ctx_(db_ctx) {}

    grpc::experimental::Interceptor* CreateClientInterceptor(grpc::experimental::ClientRpcInfo* info) override {
        return new DBSaveClientInterceptor(db_ctx_);
    }

private:
    DBContext* db_ctx_;
};

std::shared_ptr<grpc::Channel> create_channel(const grpc::string &target, DBContext* db_ctx);

#endif // CLIENT_H