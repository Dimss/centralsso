build:
	go build -o bin/centralsso main.go

grpc-ping:
	grpcurl \
     -plaintext \
     -d '{"message":"this is ping message"}' \
     localhost:5050 proto.PingService.Ping

proto:
	cd pkg/grpcsrv && \
		protoc --go_out=api/pb \
		  --go_opt=paths=source_relative \
		  --go-grpc_out=api/pb \
		  --go-grpc_opt=paths=source_relative \
		  api/ping.proto


docker:
	docker buildx build \
     --build-arg BUILD_SHA=$$(git rev-parse --short HEAD) \
	 --build-arg BUILD_VERSION=1.0.0 \
	 --platform linux/amd64 \
	 --load \
	 --tag cnvrg/centralsso:latest \
	  .