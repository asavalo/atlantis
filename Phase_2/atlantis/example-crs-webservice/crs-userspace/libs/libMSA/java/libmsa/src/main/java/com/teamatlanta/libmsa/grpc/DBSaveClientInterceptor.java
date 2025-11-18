package com.teamatlanta.libmsa.grpc;

import io.grpc.*;

public class DBSaveClientInterceptor implements ClientInterceptor {

    private final DBContext dbCtx;

    public DBSaveClientInterceptor(DBContext dbCtx) {
        this.dbCtx = dbCtx;
    }

    @Override
    public <ReqT, RespT> ClientCall<ReqT, RespT> interceptCall(
            MethodDescriptor<ReqT, RespT> method, CallOptions callOptions, Channel next) {

        return new ForwardingClientCall.SimpleForwardingClientCall<ReqT, RespT>(
                next.newCall(method, callOptions)) {

            @Override
            public void sendMessage(ReqT message) {
                MongoDBHelper.saveRequest(message, dbCtx);
                super.sendMessage(message);
            }

            @Override
            public void start(Listener<RespT> responseListener, Metadata headers) {
                super.start(new ForwardingClientCallListener.SimpleForwardingClientCallListener<RespT>(responseListener) {
                    @Override
                    public void onMessage(RespT message) {
                        MongoDBHelper.saveResponse(message, dbCtx);
                        super.onMessage(message);
                    }
                }, headers);
            }
        };
    }

    public static Channel clientChannel(String addr, DBContext dbCtx) {
        ManagedChannel channel = ManagedChannelBuilder.forTarget(addr).usePlaintext().build();
        if (dbCtx == null) {
            return channel;
        }
        ClientInterceptor interceptor = new DBSaveClientInterceptor(dbCtx);
        return ClientInterceptors.intercept(channel, interceptor);
    }
}