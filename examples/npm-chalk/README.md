# npm Example — chalk

Installs `chalk` via the Shieldoo Gate npm proxy and prints colored text to the terminal.

## Authentication

The reference `docker/config.yaml` enables proxy auth with a well-known **development token** (`test-token-123`) and the **project label** `npm-demo`.

npm requires credentials to be pre-encoded as `_auth` in `.npmrc`:

```
_auth = base64("<PROJECT>:<TOKEN>") = base64("npm-demo:test-token-123")
      = "bnBtLWRlbW86dGVzdC10b2tlbi0xMjM="
```

The bundled `.npmrc` already contains this value — no setup needed.

To change the project label:

```bash
PROJECT="my-team"
TOKEN="test-token-123"
AUTH=$(printf "%s:%s" "$PROJECT" "$TOKEN" | base64)
echo "//localhost:4873/:_auth=$AUTH"
# paste that line into .npmrc
```

## Run

```bash
# Install chalk via the proxy (registry + auth configured in .npmrc)
npm install

# Run the script
node index.mjs
```

## Expected Output

```
chalk 5.4.1 installed successfully!

Hello from Shieldoo Gate!   (green)
This package was scanned.   (blue)
Supply chain: secured.      (magenta, bold)
```

(Colors will appear in your terminal.)

## What This Tests

- npm proxy on `localhost:4873` correctly proxies package metadata and tarballs
- The `_auth` header in `.npmrc` is parsed as Basic Auth — username `npm-demo` becomes the project label
- Every downloaded artifact is stamped with `project_id = npm-demo` in the audit log
- Verify in the admin UI at `http://localhost:8080`:
  - `Projects` tab → `npm-demo` with its artifact usage
  - `Audit Log` tab → each tarball fetch tagged with the project
