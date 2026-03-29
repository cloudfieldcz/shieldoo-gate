# Go Example -- zerolog

Downloads `github.com/rs/zerolog` via the Shieldoo Gate Go module proxy and runs a minimal logging example.

## Prerequisites

- Go 1.21+ (`go version`)
- Shieldoo Gate running locally with the Go module proxy enabled on port `8087`

## Run

```bash
# Point Go at the Shieldoo Gate proxy
export GOPROXY=http://localhost:8087
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
- `.zip` download (`github.com/rs/zerolog@v1.33.0`) goes through the scan pipeline
- `.info`, `.mod`, and `list` requests are proxied as pass-through
- Check the admin UI at `http://localhost:8080` to see the scanned artifacts

## Notes

- `GONOSUMCHECK=*` is required because Shieldoo Gate does not yet implement sum.golang.org validation. Without this, Go may reject modules whose checksums do not match the upstream checksum database.
- `GONOSUMDB` can also be set to `*` if you want to skip checksum database lookups entirely.
