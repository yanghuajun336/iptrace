APP_NAME := iptrace
CMD_PATH := ./cmd/iptrace

.PHONY: build test fmt

build:
	go build -o $(APP_NAME) $(CMD_PATH)

test:
	go test ./...

fmt:
	gofmt -w $(shell find . -type f -name '*.go')
