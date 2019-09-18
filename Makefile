
all: fmt build

build: vhost

fmt:
	@go fmt ./...

vhost:
	@go build -ldflags "-w -s" -o bin/vhost

# for plugin building
# using make plugin_xxx
# example: make plugin_example, you must create folder plugin/plugin_example, must include package main in .GO file
plugin_%:
	@go build -buildmode 'plugin' -ldflags "-w -s" -o bin/$@.so ./plugin/$@

clean:
	@rm -rf bin go.sum
