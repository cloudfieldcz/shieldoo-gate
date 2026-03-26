# .NET Example — Newtonsoft.Json

Installs `Newtonsoft.Json` via the Shieldoo Gate NuGet proxy and serializes a simple object to JSON.

## Run

```bash
# Restore packages via the proxy (source configured in nuget.config)
dotnet restore

# Run the application
dotnet run
```

## Expected Output

```
Newtonsoft.Json 13.0.3 installed successfully!

Serialized JSON:
{
  "Name": "Shieldoo Gate",
  "Version": "1.0.0",
  "Secure": true
}

Done!
```

## What This Tests

- NuGet proxy on `localhost:5001` correctly proxies the V3 service index and package downloads
- The `nuget.config` file configures the package source for this project only
- Check the admin UI at `http://localhost:8080` to see the scanned artifacts
