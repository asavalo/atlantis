package grpc

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

func DBSaveClientInterceptor(dbCtx *DBContext) grpc.UnaryClientInterceptor {
	return func(
		ctx context.Context,
		method string,
		req, reply interface{},
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption,
	) error {
		// Save request to database
		if message, ok := req.(proto.Message); ok {
			SaveRequest(dbCtx, message)
		}

		// Invoke the RPC
		err := invoker(ctx, method, req, reply, cc, opts...)

		// Save response to database if no error
		if err == nil {
			if message, ok := reply.(proto.Message); ok {
				SaveResponse(dbCtx, message)
			}
		}

		return err
	}
}

func ClientChannel(addr string, dbCtx *DBContext) (*grpc.ClientConn, error) {
	opts := []grpc.DialOption{
		grpc.WithInsecure(),
	}

	if dbCtx != nil {
		interceptor := DBSaveClientInterceptor(dbCtx)
		opts = append(opts, grpc.WithUnaryInterceptor(interceptor))
	}

	return grpc.Dial(addr, opts...)
}