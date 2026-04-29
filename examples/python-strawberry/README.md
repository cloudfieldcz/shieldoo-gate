# Python Example — strawberry-graphql

Reproduction project for a usability bug: installing `strawberry-graphql==0.263.0` through
the proxy fails, while the artifact appears in the admin UI under the wheel-filename form
(`strawberry_graphql`, with underscore — see PEP 427 wheel naming).

## Authentication

Same dev defaults as `python-requests` — Basic-auth with the bootstrap label `python-demo`
and the global dev token `test-token-123`.

## Run

```bash
# Create a virtual environment
uv venv .venv
source .venv/bin/activate

# Install strawberry-graphql via the proxy
uv pip install \
    --no-cache --reinstall \
    --index-url http://python-demo:test-token-123@localhost:5010/simple/ \
    -r requirements.txt

# Run the script
python main.py
```

## What This Reproduces

- Install request goes to `/simple/strawberry-graphql/` (PEP 503 canonical, hyphen)
- Wheel filename is `strawberry_graphql-0.263.0-py3-none-any.whl` (PEP 427, underscore)
- Artifact ID derives package name from the wheel filename → stored as
  `pypi:strawberry_graphql:0.263.0:strawberry_graphql-0.263.0-py3-none-any.whl`
- Observe in the admin UI at `http://localhost:8080`:
  - Artifacts tab shows `strawberry_graphql` (underscore form)
  - Audit log entry per request — confirm whether the download succeeded or was blocked
