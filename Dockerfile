FROM golang:1.22.3 as builder
ARG BUILD_SHA
ARG BUILD_VERSION
WORKDIR /workspace

COPY go.mod go.mod
COPY go.sum go.sum
RUN go mod download
COPY main.go ./
COPY pkg/ pkg/

RUN GOOS=linux GOARCH=amd64 \
    go build \
    -o bin/centralsso main.go

FROM ubuntu:24.04
WORKDIR /opt/app-root
RUN apt update -y \
    && apt -y install ca-certificates
COPY --from=builder /workspace/bin/centralsso /opt/app-root/centralsso
CMD /opt/app-root/centralsso