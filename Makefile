SHELL := /bin/bash
include .env
export
export APP_NAME := $(basename $(notdir $(shell pwd)))

.PHONY: help
help: ## display this help screen
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

.PHONY: setup
setup: ## Setup development.
	@cp "$(go env GOROOT)/misc/wasm/wasm_exec.js" .

.PHONY: update
update: ## go modules update
	@go get -u -t ./...
	@go mod tidy
	@go mod vendor

.PHONY: dev
dev: ## Run development server.
	@rm -rf .wrangler/state/
	@wrangler d1 execute openid-connect --local --file=./schema/schema.sql
	@wrangler d1 execute openid-connect --local --file=./sample/sample.sql
	@wrangler dev

.PHONY: build
build: ## Build to WebAssembly.
	@go run github.com/syumai/workers/cmd/workers-assets-gen@v0.28.1 -mode=go
	@GOOS=js GOARCH=wasm go build -o ./build/app.wasm .


.PHONY: deploy
deploy: ## Deploy to Cloudflare Workers.
	@wrangler d1 execute openid-connect --remote --file=./schema/schema.sql
	@wrangler d1 execute openid-connect --remote --file=./sample/sample.sql
	@wrangler deploy 

.PHONY: gen
gen: ## Generate code.
	@oapi-codegen -generate types -package api api/openapi.yaml > pkg/api/types.gen.go
	@find pkg/schema -type f -not -name "*.sql" -exec rm -rf {} \;
	@sqlc generate
	@go generate ./...
	@go mod tidy
