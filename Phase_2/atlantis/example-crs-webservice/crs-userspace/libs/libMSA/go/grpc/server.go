package grpc

import (
	"context"
	"fmt"
	"log"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

type DBSaveServerInterceptor struct {
	dbCtx *DBContext
}

func NewDBSaveServerInterceptor(dbCtx *DBContext) *DBSaveServerInterceptor {
	return &DBSaveServerInterceptor{
		dbCtx: dbCtx,
	}
}

func (interceptor *DBSaveServerInterceptor) UnaryInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler) (interface{}, error) {

	// Save request to DB
	if protoReq, ok := req.(proto.Message); ok {
        SaveRequest(interceptor.dbCtx, protoReq)
    }

	// Continue with the actual request
	resp, err := handler(ctx, req)

	// Save response to DB
	if resp != nil {
        if protoResp, ok := resp.(proto.Message); ok {
            SaveResponse(interceptor.dbCtx, protoResp)
        } 
    }

	return resp, err
}

func CreateGRPCServer(dbCtx *DBContext) *grpc.Server {
	var opts []grpc.ServerOption

	if dbCtx != nil {
		interceptor := NewDBSaveServerInterceptor(dbCtx)
		opts = append(opts, grpc.UnaryInterceptor(interceptor.UnaryInterceptor))
	}

	server := grpc.NewServer(opts...)

	return server
}

func StartGRPCServer(server *grpc.Server, port int) *grpc.Server {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	go func() {
		if err := server.Serve(lis); err != nil {
			log.Fatalf("failed to serve: %v", err)
		}
	}()

	return server
}