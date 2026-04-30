.PHONY: build run test clean docker

build:
	go build -ldflags="-s -w" -o bin/gateway ./cmd/gateway

run: build
	./bin/gateway --config config/gateway.yaml

test:
	go test ./... -v -race

clean:
	rm -rf bin/

docker:
	docker compose up -d --build

docker-down:
	docker compose down

lint:
	golangci-lint run ./...

fmt:
	go fmt ./...
	goimports -w .
