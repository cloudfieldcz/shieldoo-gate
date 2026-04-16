# .NET Example — Newtonsoft.Json

Installs `Newtonsoft.Json` via the Shieldoo Gate NuGet proxy and serializes a simple object to JSON.

## Authentication

The reference `docker/config.yaml` enables proxy auth with a well-known **development token** (`test-token-123`) and the **project label** `dotnet-demo`.

NuGet credentials live in `nuget.config` under `<packageSourceCredentials>`:

```xml
<packageSourceCredentials>
  <shieldoo-gate>
    <add key="Username" value="dotnet-demo" />
    <add key="ClearTextPassword" value="test-token-123" />
  </shieldoo-gate>
</packageSourceCredentials>
```

The bundled `nuget.config` already contains this. `Username` is the **project label**; `ClearTextPassword` is the token (in production prefer a PAT + a secret store).

## Run

```bash
# Restore packages via the proxy (source + auth configured in nuget.config)
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
- `<packageSourceCredentials>` is sent as Basic Auth — username `dotnet-demo` becomes the project label
- Every downloaded `.nupkg` is stamped with `project_id = dotnet-demo` in the audit log
- Verify in the admin UI at `http://localhost:8080`:
  - `Projects` tab → `dotnet-demo`
  - `Audit Log` tab → each package fetch tagged with the project
