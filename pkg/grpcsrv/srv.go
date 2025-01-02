package grpcsrv

import (
	"context"
	pb "github.com/Dimss/centralsso/pkg/grpcsrv/api/pb/api"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	"log/slog"
	"net"
)

type Server struct {
	pb.UnimplementedPingServiceServer
}

func NewServer() *Server {
	return &Server{}
}

func (s *Server) Ping(ctx context.Context, in *pb.PingRequest) (*pb.PingResponse, error) {
	slog.Info("executing grpc ping method")
	return &pb.PingResponse{Message: "pong: " + in.Message}, nil
}

func (s *Server) Run() {
	lis, err := net.Listen("tcp", ":5050")
	if err != nil {
		log.Fatal(err)
	}
	grpcServer := grpc.NewServer()
	pb.RegisterPingServiceServer(grpcServer, s)
	log.Info("grpc server listening on :5050")
	reflection.Register(grpcServer)
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatal(err)
	}

}
