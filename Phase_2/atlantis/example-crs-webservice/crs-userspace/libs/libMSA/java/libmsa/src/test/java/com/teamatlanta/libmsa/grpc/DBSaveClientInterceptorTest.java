package com.teamatlanta.libmsa.grpc;

import io.grpc.*;
import io.grpc.stub.StreamObserver;

import org.junit.jupiter.api.*;

import static org.junit.jupiter.api.Assertions.*;

import java.util.concurrent.TimeUnit;

import userspace.TestGrpc;
import userspace.TestGrpc.TestBlockingStub;
import userspace.TestOuterClass.TestRequest;
import userspace.TestOuterClass.TestResponse;


public class DBSaveClientInterceptorTest {
    private static Server server;
    private static int serverPort = 50051;

    private static final String payload = "Team-Atlanta";
    private static final int returnCode = 1110;

    static class TestServiceImpl extends TestGrpc.TestImplBase {
        @Override
        public void testService(TestRequest request, StreamObserver<TestResponse> responseObserver) {
            assertEquals(payload, request.getTeamName());
            TestResponse response = TestResponse.newBuilder().setCnt(returnCode).build();
            responseObserver.onNext(response);
            responseObserver.onCompleted();
        }
    }

    @BeforeAll
    public static void setUpClass() throws Exception {
        // Start the gRPC server
        server = ServerBuilder.forPort(serverPort)
                .addService(new TestServiceImpl())
                .build()
                .start();

        // Allow server some time to start
        TimeUnit.SECONDS.sleep(1);
    }

    @AfterAll
    public static void tearDownClass() throws Exception {
        if (server != null) {
            server.shutdown().awaitTermination(30, TimeUnit.SECONDS);
        }
    }

    @Test
    public void testClientNoIntercept() {
        // Create channel without interceptor
        Channel channel = DBSaveClientInterceptor.clientChannel("localhost:"+serverPort, null);

        TestBlockingStub stub = TestGrpc.newBlockingStub(channel);

        // Test gRPC call
        TestRequest request = TestRequest.newBuilder().setTeamName(payload).build();
        TestResponse response = stub.testService(request);

        assertEquals(returnCode, response.getCnt());
    }

    @Test
    public void testClientWithIntercept() {
        // Mock DBContext and MongoDBHelper
        DBContext dbCtx = MongoDBHelper.dbContext(true, "unittest", "testclient");

        // Create a channel with interceptor
        Channel channel = DBSaveClientInterceptor.clientChannel("localhost:" + serverPort, dbCtx);
        TestBlockingStub stub = TestGrpc.newBlockingStub(channel);

        // Test gRPC call with interceptor
        TestRequest request = TestRequest.newBuilder().setTeamName(payload).build();
        TestResponse response = stub.testService(request);

        assertEquals(returnCode, response.getCnt());
    }
}
