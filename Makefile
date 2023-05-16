build:
	go build -o bin/centralsso main.go

docker:
	docker buildx build --build-arg BUILD_SHA=$$(git rev-parse --short HEAD) --build-arg BUILD_VERSION=1.0.0 --platform linux/amd64 --push -t cnvrg/centralsso:master .