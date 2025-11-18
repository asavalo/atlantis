package com.teamatlanta.libmsa.grpc;

import org.bson.Document;
import org.bson.types.Binary;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.ArrayList;

public class MongoDBHelper {

    public static DBContext dbContext(boolean saveMode, String moduleName, String testName) {
        if (!saveMode) {
            return null;
        }
        return new DBContext(moduleName, testName);
    }

    private static Document createDocument(Object data, String type) {
        byte[] binaryData = data.toString().getBytes();

        Document document = new Document();
        document.put("class", data.getClass().getSimpleName());
        document.put("type", type);
        document.put("datetime", LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd_HH-mm-ss")));
        document.put("protobuf_data", new Binary(binaryData));

        return document;
    }

    public static void saveRequest(Object request, DBContext dbContext) {
        Document document = createDocument(request, "request");
        dbContext.getCollection().insertOne(document);
    }

    public static void saveResponse(Object response, DBContext dbContext) {
        Document document = createDocument(response, "response");
        dbContext.getCollection().insertOne(document);
    }

    public static Binary queryId(String id, DBContext dbContext) {
        Document result = dbContext.getCollection().find(new Document("_id", id)).first();
        if (result != null) {
            return result.get("protobuf_data", Binary.class);
        }
        return null;
    }

    private static List<Document> loadData(String type, DBContext dbContext) {
        List<Document> documents = new ArrayList<>();
        dbContext.getCollection().find(new Document("type", type)).into(documents);
        return documents;
    }

    public static List<Document> loadRequests(DBContext dbContext) {
        return loadData("request", dbContext);
    }

    public static List<Document> loadResponses(DBContext dbContext) {
        return loadData("response", dbContext);
    }
}
