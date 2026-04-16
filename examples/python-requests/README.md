# Python Example — requests

Installs `requests` via the Shieldoo Gate PyPI proxy and makes a simple HTTP GET request.

## Authentication

The reference `docker/config.yaml` enables proxy auth with a well-known **development token** (`test-token-123`) and the **project label** `python-demo` — so this example exercises the full Basic-auth → project flow out of the box.

| Field | Value |
|-------|-------|
| Basic auth **username** | `python-demo` (the project label — pick any `[a-z0-9][a-z0-9_-]{0,63}`, or use `default` if you don't care about per-project segmentation) |
| Basic auth **password** | `test-token-123` (dev token, rotate for production) |

The username/password is embedded in the `--index-url` as userinfo.

## Run

```bash
# Create a virtual environment
uv venv .venv
source .venv/bin/activate

# Install requests via the proxy (PROJECT=python-demo, TOKEN=test-token-123)
uv pip install \
    --no-cache --reinstall \
    --index-url http://python-demo:test-token-123@localhost:5010/simple/ \
    -r requirements.txt

# Run the script
python main.py
```

## Expected Output

```
Fetching https://httpbin.org/get ...

Status: 200
Response (first 200 chars):
{
  "args": {},
  "headers": {
    "Accept": "*/*",
    "Accept-Encoding": "gzip, deflate",
    "Host": "httpbin.org",
    ...
  },
  ...
}

requests version: 2.32.3
Done!
```

## What This Tests

- PyPI proxy on `localhost:5010` correctly proxies the `simple/` index
- Package download (including transitive dependencies like `urllib3`, `certifi`) goes through the scan pipeline
- The Basic-auth **username** (`python-demo`) is resolved to a `projects` row and every downloaded artifact is stamped with that `project_id` in the audit log
- Verify in the admin UI at `http://localhost:8080`:
  - `Projects` tab → `python-demo` row with `created_via: lazy` and the list of pulled artifacts
  - `Audit Log` tab → each request tagged with `project_id` corresponding to `python-demo`
