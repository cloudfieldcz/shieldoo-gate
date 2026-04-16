# Go Example — zerolog

Downloads `github.com/rs/zerolog` via the Shieldoo Gate Go module proxy and runs a minimal logging example.

## Prerequisites

- Go 1.21+ (`go version`)
- Shieldoo Gate running locally with the Go module proxy enabled on port `8087`

## Authentication

The reference `docker/config.yaml` enables proxy auth with a well-known **development token** (`test-token-123`) and the **project label** `go-demo`.

The Go toolchain supports HTTP Basic auth in `GOPROXY` via userinfo in the URL:

```
GOPROXY=http://go-demo:test-token-123@localhost:8087
         │       │                    │
         │       │                    port = Shieldoo Gate Go module proxy
         │       token (Basic auth password, shared dev token)
         project label (Basic auth username)
```

Go's ordinary `http://` handler forwards credentials as `Authorization: Basic …`, which Shieldoo Gate reads as Basic auth.

## Run

```bash
# Point Go at the Shieldoo Gate proxy (PROJECT=go-demo, TOKEN=test-token-123)
export GOPROXY="http://go-demo:test-token-123@localhost:8087"
export GONOSUMCHECK=*

# Download dependencies through the proxy
go mod download

# Run the example
go run main.go
```

## Expected Output

```
INF Hello from Shieldoo Gate Go example!
INF Dependency loaded successfully library=zerolog version=v1.33.0
WRN This is a sample warning message
INF Done!
```

## What This Tests

- Go module proxy on `localhost:8087` correctly proxies the GOPROXY protocol
- The Basic-auth username `go-demo` is resolved to a `projects` row
- `.zip` download (`github.com/rs/zerolog@v1.33.0`) goes through the scan pipeline and is stamped with `project_id = go-demo` in the audit log
- `.info`, `.mod`, and `list` requests are proxied as pass-through
- Verify in the admin UI at `http://localhost:8080`:
  - `Projects` tab → `go-demo` with its artifact usage
  - `Audit Log` tab → each module fetch tagged with the project

## Notes

- `GONOSUMCHECK=*` is required because Shieldoo Gate does not yet implement sum.golang.org validation. Without this, Go may reject modules whose checksums do not match the upstream checksum database.
- `GONOSUMDB` can also be set to `*` if you want to skip checksum database lookups entirely.
- For production, use `netrc`-style credentials (`GOAUTH=netrc`) instead of embedding the token in `GOPROXY` so it doesn't leak into shell history or `go env`.
