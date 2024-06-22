.PHONY: dev
dev:
	wrangler dev

.PHONY: build
build:
	go run github.com/syumai/workers/cmd/workers-assets-gen@v0.23.1
	tinygo build -o ./build/app.wasm -target wasm -no-debug ./...

.PHONY: deploy
deploy:
	wrangler deploy

.PHONY: gen
gen: ## Generate code.
	@oapi-codegen -generate types -package api api/openapi.yaml > pkg/api/types.gen.go
	@go generate ./...
	@go mod tidy
