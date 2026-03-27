# Python Example — requests

Installs `requests` via the Shieldoo Gate PyPI proxy and makes a simple HTTP GET request.

## Run

```bash
# Create a virtual environment
uv venv .venv
source .venv/bin/activate

# Install requests via the proxy
uv pip install --no-cache --reinstall --index-url http://localhost:5010/simple/ -r requirements.txt

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
- Check the admin UI at `http://localhost:8080` to see the scanned artifacts
