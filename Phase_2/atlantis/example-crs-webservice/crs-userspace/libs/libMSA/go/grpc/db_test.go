package grpc

import (
	//"context"
	"testing"
	//"log"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson/primitive"
	pb "teamatlanta.com/libmsa/sample/proto"
	"google.golang.org/protobuf/proto"
)

func TestSaveRequest(t *testing.T) {
	// Set up MongoDB context
	dbCtx := NewDBContext(true, "unittest", "testdb")
	defer dbCtx.CloseDBContext()

	// Prepare request data
	data := "Team Atlanta"
	request := &pb.TestRequest{
		TeamName: data,
	}

	// Save the request
	result, err := SaveRequest(dbCtx, request)
	assert.NoError(t, err)
	assert.NotNil(t, result.InsertedID)
}

func TestQueryByID(t *testing.T) {
	// Set up MongoDB context
	dbCtx := NewDBContext(true, "unittest", "testdb")
	defer dbCtx.CloseDBContext()

	// Prepare and save response data
	data := "Team Atlanta"
	response := &pb.TestRequest{
		TeamName: data,
	}

	result, err := SaveResponse(dbCtx, response)
	assert.NoError(t, err)
	assert.NotNil(t, result.InsertedID)

	// Query the document by ID
	objectID, ok := result.InsertedID.(primitive.ObjectID)
	if !ok {
		t.Fatal("InsertedID is not an ObjectID")
	}

	queriedData := QueryByID(dbCtx, objectID.Hex())
	assert.NotNil(t, queriedData)

	// Deserialize protobuf data
	var queriedResponse pb.TestRequest
	err = proto.Unmarshal(queriedData, &queriedResponse)
	assert.NoError(t, err)
	assert.Equal(t, data, queriedResponse.TeamName)
}

func TestLoadRequests(t *testing.T) {
	// Set up MongoDB context
	dbCtx := NewDBContext(true, "unittest", "testdb")
	defer dbCtx.CloseDBContext()

	// Prepare and save request data
	data := "Team Atlanta"
	request := &pb.TestRequest{
		TeamName: data,
	}

	result, err := SaveRequest(dbCtx, request)
	assert.NoError(t, err)
	assert.NotNil(t, result.InsertedID)

	// Load all requests
	results := LoadRequests(dbCtx)
	assert.Greater(t, len(results), 0)
}