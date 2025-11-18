package grpc

import (
	"context"
	"log"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	pb "teamatlanta.com/libmsa/sample/proto"
)

const (
	payload    = "Team-Atlanta"
	returnCode = 1110
)

type TestService struct {
	pb.UnimplementedTestServer
}

func (s *TestService) TestService(ctx context.Context, req *pb.TestRequest) (*pb.TestResponse, error) {
	if req.TeamName != payload {
		return nil, grpc.Errorf(codes.InvalidArgument, "Invalid team name")
	}
	return &pb.TestResponse{Cnt: returnCode}, nil
}

func startTestServer() *grpc.Server {
	lis, err := net.Listen("tcp", ":50051")
    if err != nil {
        log.Fatalf("failed to listen: %v", err)
    }

	s := grpc.NewServer()
	pb.RegisterTestServer(s, &TestService{})

	go func() {
		if err := s.Serve(lis); err != nil {
			log.Fatalf("Server exited with error: %v", err)
		}
	}()
	return s
}

func TestClientNoIntercept(t *testing.T) {
	// Start test server
	server := startTestServer()
	defer server.Stop()

	// Create a connection to the server
	conn, err := ClientChannel("localhost:50051", nil)
	if err != nil {
		t.Fatalf("Failed to dial bufnet: %v", err)
	}
	defer conn.Close()

	client := pb.NewTestClient(conn)
	req := &pb.TestRequest{TeamName: payload}

	// Set a context with a timeout
    ctx, cancel := context.WithTimeout(context.Background(), time.Second)
    defer cancel()

	res, err := client.TestService(ctx, req)
	if err != nil {
		t.Fatalf("TestService call failed: %v", err)
	}

	if res.Cnt != returnCode {
		t.Fatalf("Expected %d, got %d", returnCode, res.Cnt)
	}
}

func TestClientIntercept(t *testing.T) {
	// Start test server
	server := startTestServer()
	defer server.Stop()

	// Create a connection to the server
	dbCtx := NewDBContext(true, "unittest", "testclient")
	conn, err := ClientChannel("localhost:50051", dbCtx)
	if err != nil {
		t.Fatalf("Failed to dial bufnet: %v", err)
	}
	defer conn.Close()

	client := pb.NewTestClient(conn)
	req := &pb.TestRequest{TeamName: payload}

	// Set a context with a timeout
    ctx, cancel := context.WithTimeout(context.Background(), time.Second)
    defer cancel()

	res, err := client.TestService(ctx, req)
	if err != nil {
		t.Fatalf("TestService call failed: %v", err)
	}

	if res.Cnt != returnCode {
		t.Fatalf("Expected %d, got %d", returnCode, res.Cnt)
	}
}