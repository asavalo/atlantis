#include "libmsa/grpc/client.h"
#include "libmsa/grpc/db.h"
#include <grpcpp/channel.h>
#include <grpcpp/create_channel.h>
#include <memory>

void DBSaveClientInterceptor::Intercept(grpc::experimental::InterceptorBatchMethods* methods) {
    if (methods->QueryInterceptionHookPoint(grpc::experimental::InterceptionHookPoints::PRE_SEND_INITIAL_METADATA)) {
        const google::protobuf::Message* request = static_cast<const google::protobuf::Message*>(methods->GetSendMessage());
        save_request(*request, *db_ctx_);
    }

    if (methods->QueryInterceptionHookPoint(grpc::experimental::InterceptionHookPoints::POST_RECV_MESSAGE)) {
        const google::protobuf::Message* response = static_cast<const google::protobuf::Message*>(methods->GetRecvMessage());
        save_response(*response, *db_ctx_);
    }

    methods->Proceed();
}

std::shared_ptr<grpc::Channel> create_channel(const grpc::string &target, DBContext* db_ctx){
    if (db_ctx == nullptr) {
        return grpc::CreateChannel(target, grpc::InsecureChannelCredentials());
    }
    std::vector<std::unique_ptr<grpc::experimental::ClientInterceptorFactoryInterface>> interceptors;
    interceptors.push_back(std::make_unique<DBSaveClientInterceptorFactory>(db_ctx));
    grpc::ChannelArguments channel_args;
    return grpc::experimental::CreateCustomChannelWithInterceptors(target, grpc::InsecureChannelCredentials(),channel_args, std::move(interceptors));
}