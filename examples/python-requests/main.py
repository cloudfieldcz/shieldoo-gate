"""Minimal example: fetch a URL using the requests library."""

import requests


def main():
    url = "https://httpbin.org/get"
    print(f"Fetching {url} ...\n")

    resp = requests.get(url, timeout=10)

    print(f"Status: {resp.status_code}")
    print(f"Response (first 200 chars):\n{resp.text[:200]}\n")
    print(f"requests version: {requests.__version__}")
    print("Done!")


if __name__ == "__main__":
    main()
