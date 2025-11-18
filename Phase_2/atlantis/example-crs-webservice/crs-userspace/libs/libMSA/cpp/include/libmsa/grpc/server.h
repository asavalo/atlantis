#include <grpcpp/grpcpp.h>
#include "db.h"

class DBSaveServerInterceptor : public grpc::experimental::Interceptor {
public:
    explicit DBSaveServerInterceptor(DBContext* db_ctx) : db_ctx_(db_ctx) {}

    void Intercept(grpc::experimental::InterceptorBatchMethods* methods) override;

private:
    DBContext* db_ctx_;
};

class DBSaveServerInterceptorFactory : public grpc::experimental::ServerInterceptorFactoryInterface {
public:
    explicit DBSaveServerInterceptorFactory(DBContext* db_ctx) : db_ctx_(db_ctx) {}

    grpc::experimental::Interceptor* CreateServerInterceptor(grpc::experimental::ServerRpcInfo* info) override {
        return new DBSaveServerInterceptor(db_ctx_);
    }
private:
    DBContext* db_ctx_;
};

std::unique_ptr<grpc::Server> open_port(int port, grpc::Service* service, DBContext* db_ctx);