# workers

[![Go Reference](https://pkg.go.dev/badge/github.com/syumai/workers.svg)](https://pkg.go.dev/github.com/syumai/workers)
[![Discord Server](https://img.shields.io/discord/1095344956421447741?logo=discord&style=social)](https://discord.gg/tYhtatRqGs)

* `workers` is a package to run an HTTP server written in Go on [Cloudflare Workers](https://workers.cloudflare.com/).
* This package can easily serve *http.Handler* on Cloudflare Workers.
* Caution: This is an experimental project.

## Features

* [x] serve http.Handler
* [ ] R2
  - [x] Head
  - [x] Get
  - [x] Put
  - [x] Delete
  - [x] List
  - [ ] Options for R2 methods
* [ ] KV
  - [x] Get
  - [x] List
  - [x] Put
  - [x] Delete
  - [ ] Options for KV methods
* [x] Cache API
* [ ] Durable Objects
  - [x] Calling stubs
* [x] D1 (alpha)
* [x] Environment variables
* [x] FetchEvent
* [x] Cron Triggers
* [x] TCP Sockets
* [x] Queues
  - [x] Producer
  - [x] Consumer

## Installation

```
go get github.com/syumai/workers
```

## Usage

implement your http.Handler and give it to `workers.Serve()`.

```go
func main() {
	var handler http.HandlerFunc = func (w http.ResponseWriter, req *http.Request) { ... }
	workers.Serve(handler)
}
```

or just call `http.Handle` and `http.HandleFunc`, then invoke `workers.Serve()` with nil.

```go
func main() {
	http.HandleFunc("/hello", func (w http.ResponseWriter, req *http.Request) { ... })
	workers.Serve(nil) // if nil is given, http.DefaultServeMux is used.
}
```

For concrete examples, see `_examples` directory.

## Quick Start

First, please install the following tools:

* Node.js (and npm)
* [wrangler](https://developers.cloudflare.com/workers/wrangler/)
  - You can install it by running `npm install -g wrangler`.
* Go 1.24.0 or later
* [gonew](https://pkg.go.dev/golang.org/x/tools/cmd/gonew)
  - You can install it by running `go install golang.org/x/tools/cmd/gonew@latest`

After installation, please run the following commands.

```console
gonew github.com/syumai/workers/_templates/cloudflare/worker-go your.module/my-app # e.g. github.com/syumai/my-app
cd my-app
go mod tidy
make dev # start running dev server
curl http://localhost:8787/hello # outputs "Hello!"
```

If you want a more detailed description, please refer to the README.md file in the generated directory.

## FAQ

### How do I deploy a worker implemented in this package?

To deploy a Worker, the following steps are required.

* Create a worker project using [wrangler](https://developers.cloudflare.com/workers/wrangler/).
* Build a Wasm binary.
* Upload a Wasm binary with a JavaScript code to load and instantiate Wasm (for entry point).

The [worker-go template](https://github.com/syumai/workers/tree/main/_templates/cloudflare/worker-go) contains all the required files, so I recommend using this template.

But Go (not TinyGo) with many dependencies may exceed the size limit of the Worker (3MB for free plan, 10MB for paid plan). In that case, you can use the [TinyGo template](https://github.com/syumai/workers/tree/main/_templates/cloudflare/worker-tinygo) instead.

### Where can I have discussions about contributions, or ask questions about how to use the library?

You can do both through GitHub Issues. If you want to have a more casual conversation, please use the [Discord server](https://discord.gg/tYhtatRqGs).
