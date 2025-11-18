package com.teamatlanta.kafka.converter;

import org.apache.kafka.connect.data.Schema;
import org.apache.kafka.connect.data.SchemaAndValue;
import org.apache.kafka.connect.errors.DataException;
import org.apache.kafka.connect.storage.Converter;
import org.bson.BsonBinary;
import org.bson.BsonDateTime;
import org.bson.BsonDocument;
import org.bson.BsonString;

import java.util.Map;

public class MongoDbConverter implements Converter {
    @Override
    public void configure(Map<String, ?> configs, boolean isKey) {
    }

    @Override
    public byte[] fromConnectData(String topic, Schema schema, Object value) {
        if (value == null) {
            return null;
        }

        try {
            BsonDocument bsonDocument = (BsonDocument) value;

            BsonBinary bsonBinary = bsonDocument.getBinary("message");
            byte[] messageBytes = bsonBinary.getData();

            return messageBytes;
        } catch (Exception e) {
            throw new DataException("Error while serializing BSON data", e);
        }
    }

    @Override
    public SchemaAndValue toConnectData(String topic, byte[] value) {
        if (value == null) {
            return null;
        }

        try {
            BsonDocument bsonDocument = new BsonDocument();
            bsonDocument.put("topic", new BsonString(topic));
            bsonDocument.put("timestamp", new BsonDateTime(System.currentTimeMillis()));
            bsonDocument.put("message", new BsonBinary(value));

            return new SchemaAndValue(null, bsonDocument);
        } catch (Exception e) {
            throw new DataException("Error while deserializing JSON data", e);
        }
    }
}