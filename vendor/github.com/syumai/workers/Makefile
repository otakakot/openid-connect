SHELL := /bin/bash

.PHONY: test
test:
	@PATH=$(CURDIR)/misc/wasm:$$PATH GOOS=js GOARCH=wasm go test ./...

.PHONY: build-examples
build-examples:
	for dir in $(shell find ./_examples -maxdepth 1 -type d); do \
		if [ $$dir = "./_examples" ]; then continue; fi; \
		echo 'build:' $$dir; \
		cd $$dir && GOOS=js GOARCH=wasm go build -o ./build/app.wasm; \
		cd ../../; \
	done
