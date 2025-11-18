#include "libmsa/grpc/server.h"

void DBSaveServerInterceptor::Intercept(grpc::experimental::InterceptorBatchMethods* methods) {
    if (methods->QueryInterceptionHookPoint(grpc::experimental::InterceptionHookPoints::PRE_SEND_INITIAL_METADATA)) {
        const google::protobuf::Message* request = static_cast<const google::protobuf::Message*>(methods->GetSendMessage());
        save_response(*request, *db_ctx_);
    }

    if (methods->QueryInterceptionHookPoint(grpc::experimental::InterceptionHookPoints::POST_RECV_MESSAGE)) {
        const google::protobuf::Message* response = static_cast<const google::protobuf::Message*>(methods->GetRecvMessage());
        save_request(*response, *db_ctx_);
    }

    methods->Proceed();
}

std::unique_ptr<grpc::Server> open_port(int port, grpc::Service* service, DBContext* db_ctx) {
    std::string server_address = "0.0.0.0:" + std::to_string(port);

    grpc::ServerBuilder builder;
    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
    builder.RegisterService(service);

    if (db_ctx != nullptr) {
        std::vector<std::unique_ptr<grpc::experimental::ServerInterceptorFactoryInterface>> interceptor_factories;
        interceptor_factories.push_back(std::unique_ptr<grpc::experimental::ServerInterceptorFactoryInterface>(new DBSaveServerInterceptorFactory(db_ctx)));
        builder.experimental().SetInterceptorCreators(std::move(interceptor_factories));
    }
    std::unique_ptr<grpc::Server> server(builder.BuildAndStart());
    return server;
}