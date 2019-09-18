
all: fmt build

build: vhost

fmt:
	@go fmt ./...

vhost:
	@go build -o bin/vhost

clean:
	@rm -rf bin go.sum
