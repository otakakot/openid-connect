# openid-coneect

## Preparation

```shell
brew tap tinygo-org/tools
brew install tinygo
```

```shell
export PATH="$(go env GOROOT)/misc/wasm:${PATH}"
```

## Requirements

- Node.js
- [wrangler](https://developers.cloudflare.com/workers/wrangler/)
  - just run `npm install -g wrangler`
- tinygo 0.29.0 or later

## create d1

ref: https://developers.cloudflare.com/d1/get-started


## create database

```shell
wrangler d1 create openid-connect
```

## install sqlc

```shell
go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest
```
