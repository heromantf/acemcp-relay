# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

acemcp-relay is a Go HTTP proxy server that relays requests to the Augment API. It uses the Gin web framework and supports both standard HTTP requests and Server-Sent Events (SSE) streaming.

## Build and Run Commands

```bash
# Build the application
go build -o acemcp-relay.exe .

# Run the application (listens on 127.0.0.1:3009)
go run main.go

# Download dependencies
go mod download

# After modifying code, clean up dependencies and verify build
go mod tidy && go build .
```

## Architecture

The server is a single-file application (`main.go`) with these key components:

- **Authentication middleware**: Bearer token validation against `AUTH_TOKEN`
- **Standard proxy handler** (`proxyHandler`): Forwards POST requests to allowed paths
- **SSE proxy handler** (`sseProxyHandler`): Handles streaming responses for `/chat-stream` with special request validation
- **Request validation**: The `/chat-stream` endpoint enforces strict payload constraints (specific fields must be null/empty, mode must be "CHAT", message must start with a specific prefix)

## Key Constants

- Server binds to `127.0.0.1:3009`
- Logs output to both console and `gin.log` file
- `allowedPaths`: Standard API endpoints that are proxied
- `ssePaths`: Streaming endpoints (currently only `/chat-stream`)
