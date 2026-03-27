# npm Example — chalk

Installs `chalk` via the Shieldoo Gate npm proxy and prints colored text to the terminal.

## Run

```bash
# Install chalk via the proxy (registry configured in .npmrc)
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
- The `.npmrc` file configures the registry for this project only (does not affect other projects)
- Check the admin UI at `http://localhost:8080` to see the scanned artifacts
