package com.teamatlanta.libmsa.grpc;

import userspace.TestOuterClass.TestRequest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.bson.Document;

public class MongoDBHelperTest {
    private DBContext dbContext;
    private String data;
    private TestRequest request;

    @BeforeEach
    public void setUp() {
        this.dbContext = MongoDBHelper.dbContext(true, "unittest", "testdb");
        this.data = "Team Atlanta";
        this.request = TestRequest.newBuilder().setTeamName(data).build();
    }

    @AfterEach
    public void tearDown() {

    }

    @Test
    public void testSaveRequest() {
        MongoDBHelper.saveRequest(request, dbContext);
    }

    @Test
    public void testLoadRequests() {
        MongoDBHelper.saveRequest(request, dbContext);

        List<Document> results = MongoDBHelper.loadRequests(dbContext);

        assertTrue(results.size() > 0);
    }
}
