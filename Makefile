
_UPX_ENV ?= --no-env
_UPX ?= $(shell which upx)

ifneq ($(UPX),)
_UPX := $(shell [ -f $(UPX) ] && echo $(UPX) || echo $(UPX)/upx)
endif

ifneq ($(_UPX),)
_UPX := $(shell [ -x $(_UPX) ] && echo $(_UPX) || which upx)
endif

ifeq ($(UPX_FAST),)
_UPX_ENV += --ultra-brute -9
else
_UPX_ENV += -1
endif
.PHONY: all
all: build

.PHONY: build
build: init fmt vhost

.PHONY: release
release: init fmt release_vhost

.PHONY: release_build
release_build:
ifneq ($(BINNAME),)
	@rm -rf release/$(BINNAME)
ifneq ($(_UPX),)
	@$(_UPX) $(_UPX_ENV) bin/$(BINNAME) -o release/$(BINNAME)
else
	@echo -e "\033[32;1m### \033[31;1mNo UPX be found, Uncompressed provided!\033[32;1m ###\033[0m"
	@cp -raf bin/$(BINNAME) release/$(BINNAME)
endif
endif

.PHONY: init
init:
	@mkdir -p bin release

.PHONY: fmt
fmt:
	@go fmt ./...

.PHONY: vhost
vhost:
	@go build -ldflags "-w -s" -o bin/$@

.PHONY: release_vhost
release_vhost: vhost
	@BINNAME=$^ make -C . release_build

# for plugin building
# using make plugin_xxx
# example: make plugin_example, you must create folder plugin/plugin_example, must include package main in .GO file
.PHONY: plugin_%
plugin_%:
	@go build -buildmode 'plugin' -ldflags "-w -s" -o bin/$@.so ./plugin/$@

.PHONY: clean
clean:
	@go clean -i -n -x -cache
	@rm -rf bin go.sum

.PHONY: distclean
distclean:
	@go clean -i -n -x --modcache
	@rm -rf bin go.sum release
