package com.teamatlanta.libmsa.grpc;

import io.grpc.*;

import java.io.IOException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class DBSaveServerInterceptor implements ServerInterceptor {
    private final DBContext dbContext;

    public DBSaveServerInterceptor(DBContext dbContext) {
        this.dbContext = dbContext;
    }

    @Override
    public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(
        ServerCall<ReqT, RespT> call,
        Metadata headers,
        ServerCallHandler<ReqT, RespT> next
    ) {

        ServerCall<ReqT, RespT> serverCall = new ForwardingServerCall.SimpleForwardingServerCall<ReqT, RespT>(call) {
            @Override
            public void sendMessage(RespT message) {
                // Intercept the outgoing response
                MongoDBHelper.saveResponse(message, dbContext);
                
                super.sendMessage(message);
            }
        };

        ServerCall.Listener<ReqT> nextListener = next.startCall(serverCall, headers);
        
        return new ForwardingServerCallListener.SimpleForwardingServerCallListener<ReqT>(nextListener) {
            @Override
            public void onMessage(ReqT message) {
                // Intercept the incoming request
                MongoDBHelper.saveRequest(message, dbContext);
                
                super.onMessage(message);
            }
        };
    }

    public static Server openPort(int port, BindableService servicer, DBContext dbContext) throws IOException {
        ExecutorService executor = Executors.newFixedThreadPool(1);
        
        ServerBuilder<?> serverBuilder = ServerBuilder.forPort(port)
                .executor(executor).addService(servicer);
        
        if (dbContext != null) {
            // Add the interceptor if dbContext is provided
            serverBuilder = serverBuilder.intercept(new DBSaveServerInterceptor(dbContext));
        }

        Server server = serverBuilder.build().start();

        return server;
    }
}