package grpc

import (
	"context"
	"log"
	"testing"
	"time"

	"google.golang.org/grpc"
	pb "teamatlanta.com/libmsa/sample/proto"
)

func DoClient(t *testing.T) {
	conn, err := grpc.Dial("localhost:50051", grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
        log.Fatalf("did not connect: %v", err)
    }
    defer conn.Close()
    c := pb.NewTestClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
    defer cancel()
    r, err := c.TestService(ctx, &pb.TestRequest{TeamName: payload})

	if err != nil {
		t.Fatalf("TestService call failed: %v", err)
	}

	if r.Cnt != returnCode {
		t.Fatalf("Expected %d, got %d", returnCode, r.Cnt)
	}
}

func TestServerNoIntercept(t *testing.T) {
	s := CreateGRPCServer(nil)
	pb.RegisterTestServer(s, &TestService{})
	s = StartGRPCServer(s, 50051)

	DoClient(t)

	time.Sleep(3 * time.Second)
	s.Stop()
}

func TestServerIntercept(t *testing.T) {
	dbCtx := NewDBContext(true, "unittest", "testserver")
	s := CreateGRPCServer(dbCtx)
	pb.RegisterTestServer(s, &TestService{})
	s = StartGRPCServer(s, 50051)

	DoClient(t)

	time.Sleep(3 * time.Second)
	s.Stop()
}