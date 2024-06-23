.PHONY: help
help: ## display this help screen
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

.PHONY: dev
dev: ## Run development server.
	@wrangler dev

.PHONY: build
build: ## Build to WebAssembly.
	@go run github.com/syumai/workers/cmd/workers-assets-gen@v0.23.1
	@tinygo build -o ./build/app.wasm -target wasm -no-debug ./...

.PHONY: deploy
deploy: ## Deploy to Cloudflare Workers.
	@wrangler deploy 

.PHONY: gen
gen: ## Generate code.
	@oapi-codegen -generate types -package api api/openapi.yaml > pkg/api/types.gen.go
	@go generate ./...
	@go mod tidy
