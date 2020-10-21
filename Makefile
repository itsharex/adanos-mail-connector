Version := $(shell date "+%Y%m%d%H%M")
GitCommit := $(shell git rev-parse HEAD)
DIR := $(shell pwd)
LDFLAGS := -s -w -X main.Version=$(Version) -X main.GitCommit=$(GitCommit)

run: build
	./build/debug/adanos-mail-connector

build:
	go build -race -ldflags "$(LDFLAGS)" -o build/debug/adanos-mail-connector main.go

build-release:
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o build/release/adanos-mail-connector-darwin main.go
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o build/release/adanos-mail-connector.exe main.go
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o build/release/adanos-mail-connector-linux main.go
	CGO_ENABLED=0 GOOS=linux GOARCH=arm go build -ldflags "$(LDFLAGS)" -o build/release/adanos-mail-connector-arm main.go

clean:
	rm -fr build/debug/adanos-* build/release/adanos-*

.PHONY: run build build-release clean
