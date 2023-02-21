build:
	go build -o bin/centralsso main.go

docker:
	docker buildx build --build-arg BUILD_SHA=$$(git rev-parse --short HEAD) --build-arg BUILD_VERSION=1.0.0 --platform linux/amd64 --push -t cnvrg/centralsso:$$(git rev-parse --short HEAD) .

generate:
	openssl req  -nodes -new -x509 -days 9999999999999999  -keyout server1.key -out server1.cert