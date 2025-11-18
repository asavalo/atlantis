package grpc

import (
	"context"
	"time"
	"log"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"google.golang.org/protobuf/proto"
)

type DBContext struct {
	client     *mongo.Client
	collection *mongo.Collection
}

func NewDBContext(saveMode bool, moduleName string, testName string) *DBContext {
	if saveMode == false {
		return nil
	}
	clientOptions := options.Client().ApplyURI("mongodb://localhost:27017/")
	client, err := mongo.Connect(context.TODO(), clientOptions)
	if err != nil {
		return nil
	}
	db := client.Database(moduleName)
	collection := db.Collection(testName)

	return &DBContext{
		client:     client,
		collection: collection,
	}
}

func (dbCtx *DBContext) CloseDBContext() {
	if err := dbCtx.client.Disconnect(context.TODO()); err != nil {
		log.Fatal(err)
	}
}

func createDocument(data proto.Message, docType string) bson.M {
	binaryData, err := proto.Marshal(data)
	if err != nil {
		log.Fatal(err)
	}

	document := bson.M{
		"class":        proto.MessageName(data),
		"type":         docType,
		"datetime":     time.Now().Format("2006-01-02_15-04-05"),
		"protobufData": binaryData,
	}
	return document
}

func SaveRequest(dbCtx *DBContext, request proto.Message) (*mongo.InsertOneResult, error) {
	document := createDocument(request, "request")
	return dbCtx.collection.InsertOne(context.TODO(), document)
}

func SaveResponse(dbCtx *DBContext, response proto.Message) (*mongo.InsertOneResult, error) {
	document := createDocument(response, "response")
	return dbCtx.collection.InsertOne(context.TODO(), document)
}

func QueryByID(dbCtx *DBContext, id string) []byte {
	var result bson.M
	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		log.Fatal(err)
	}

	err = dbCtx.collection.FindOne(context.TODO(), bson.M{"_id": objectID}).Decode(&result)
	if err != nil {
		return nil
	}

	protobufData, ok := result["protobufData"].(primitive.Binary)
	if !ok {
		log.Fatal(err)
	}
	return protobufData.Data
}

func LoadRequests(dbCtx *DBContext) []bson.M {
	cursor, err := dbCtx.collection.Find(context.TODO(), bson.M{"type": "request"})
	if err != nil {
		log.Fatal(err)
	}
	var requests []bson.M
	if err = cursor.All(context.TODO(), &requests); err != nil {
		log.Fatal(err)
	}
	return requests
}

func LoadResponses(dbCtx *DBContext) []bson.M {
	cursor, err := dbCtx.collection.Find(context.TODO(), bson.M{"type": "response"})
	if err != nil {
		log.Fatal(err)
	}
	var responses []bson.M
	if err = cursor.All(context.TODO(), &responses); err != nil {
		log.Fatal(err)
	}
	return responses
}