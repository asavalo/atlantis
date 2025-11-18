package com.teamatlanta.libmsa.grpc;

import io.grpc.*;
import io.grpc.stub.StreamObserver;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

import userspace.TestGrpc;
import userspace.TestGrpc.TestBlockingStub;
import userspace.TestOuterClass.TestRequest;
import userspace.TestOuterClass.TestResponse;

public class DBSaveServerInterceptorTest {
    private static final String payload = "Team-Atlanta";
    private static final int returnCode = 1110;
    private static int serverPort = 50051;

    private ManagedChannel channel;
    private TestBlockingStub stub;

    public static class TestServiceImpl extends TestGrpc.TestImplBase {
        @Override
        public void testService(TestRequest request, StreamObserver<TestResponse> responseObserver) {
            assertEquals(payload, request.getTeamName());

            TestResponse response = TestResponse.newBuilder()
                    .setCnt(returnCode)
                    .build();
            responseObserver.onNext(response);
            responseObserver.onCompleted();
        }
    }

    @BeforeEach
    public void setUp() throws IOException {
        channel = ManagedChannelBuilder.forTarget("localhost:"+serverPort).usePlaintext().build();
        stub = TestGrpc.newBlockingStub(channel);
    }

    @AfterEach
    public void tearDown() throws InterruptedException {
        if (channel != null) {
            channel.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
        }
    }

    private void doClient() {
        TestRequest request = TestRequest.newBuilder()
                .setTeamName(payload)
                .build();
        TestResponse response = stub.testService(request);
        assertEquals(returnCode, response.getCnt());
    }

    @Test
    public void testServerNoInterceptor() throws Exception {
        Server server = DBSaveServerInterceptor.openPort(serverPort, new TestServiceImpl(), null);

        doClient();
        Thread.sleep(3000);

        server.shutdown();
    }

    @Test
    public void testServerWithInterceptor() throws Exception {
        DBContext dbCtx = MongoDBHelper.dbContext(true, "unittest", "testserver");

        Server server = DBSaveServerInterceptor.openPort(serverPort, new TestServiceImpl(), dbCtx);

        doClient();
        Thread.sleep(3000);

        server.shutdown();
    }
}
