package com.teamatlanta.libmsa.grpc;

import com.mongodb.MongoClient;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import org.bson.Document;

public class DBContext implements AutoCloseable {
    private String moduleName;
    private String testName;
    private MongoClient client;
    private MongoDatabase database;
    private MongoCollection<Document> collection;

    public DBContext(String moduleName, String testName) {
        this.moduleName = moduleName;
        this.testName = testName;
        this.client = new MongoClient("localhost", 27017);
        this.database = client.getDatabase(this.moduleName);
        this.collection = database.getCollection(this.testName);
    }

    @Override
    public void close() {
        client.close();
    }

    public MongoCollection<Document> getCollection() {
        return this.collection;
    }
}