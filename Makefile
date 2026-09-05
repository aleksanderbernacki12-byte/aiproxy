BINARY    := aiproxy
CMD       := ./cmd/aiproxy
BUILD_DIR := bin

.PHONY: all build build-all darwin-arm64 darwin-amd64 windows linux test vet fmt clean

all: build

build:
	go build -o $(BUILD_DIR)/$(BINARY) $(CMD)

# Cross-compile for every target platform in one go.
build-all: darwin-arm64 darwin-amd64 windows linux

darwin-arm64: ## macOS, Apple Silicon
	GOOS=darwin GOARCH=arm64 go build -o $(BUILD_DIR)/$(BINARY)-darwin-arm64 $(CMD)

darwin-amd64: ## macOS, Intel
	GOOS=darwin GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY)-darwin-amd64 $(CMD)

windows: ## Windows, amd64
	GOOS=windows GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY)-windows-amd64.exe $(CMD)

linux: ## Linux, amd64
	GOOS=linux GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY)-linux-amd64 $(CMD)

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -l .

clean:
	rm -rf $(BUILD_DIR)
