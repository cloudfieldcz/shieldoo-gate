#!/usr/bin/env bash
# gen-npm-nuget.sh — build minimal npm + NuGet private-index fixtures into www/.
# Run once; commit the generated www/ artifacts. Mirrors gen-package.sh (PyPI).
#
# Layout produced (served by the shared private-index Caddy at https://private-index:8443):
#   npm packument:    www/npm/<pkg>.json            (Caddy routes GET /<pkg> here)
#   npm tarball:      www/<pkg>/-/<pkg>-<ver>.tgz    (file_server, path == /{pkg}/-/{tgz})
#   nuget registration: www/v3/registration/<id>/index.json
#   nuget nupkg:      www/v3-flatcontainer/<id>/<ver>/<id>.<ver>.nupkg
#
# The download URLs embedded in the metadata point at https://private-index:8443
# WITHOUT a path prefix so that, after the gate rewrites them to its own origin,
# they route back to the gate's bare /{pkg}/-/{tgz} and /v3-flatcontainer/ routes.
set -euo pipefail
cd "$(dirname "$0")"
WWW="www"
HOST="https://private-index:8443"

# ---------------------------------------------------------------------------
# npm — clean package mycompany-npm-lib@1.0.0
# ---------------------------------------------------------------------------
build_npm() { # name version
  local name="$1" ver="$2" dir tgz sha1 sha512
  dir="$(mktemp -d)"
  mkdir -p "$dir/package"
  cat > "$dir/package/package.json" <<EOF
{ "name": "$name", "version": "$ver", "main": "index.js", "license": "MIT" }
EOF
  printf 'module.exports = function () { return "hi from %s"; };\n' "$name" > "$dir/package/index.js"
  mkdir -p "$WWW/$name/-"
  tgz="$WWW/$name/-/$name-$ver.tgz"
  tar czf "$tgz" -C "$dir" package
  rm -rf "$dir"
  sha1="$(openssl dgst -sha1 "$tgz" | awk '{print $2}')"
  sha512="$(openssl dgst -sha512 -binary "$tgz" | openssl base64 -A)"
  mkdir -p "$WWW/npm"
  cat > "$WWW/npm/$name.json" <<EOF
{
  "name": "$name",
  "dist-tags": { "latest": "$ver" },
  "versions": {
    "$ver": {
      "name": "$name",
      "version": "$ver",
      "main": "index.js",
      "license": "MIT",
      "dist": {
        "shasum": "$sha1",
        "integrity": "sha512-$sha512",
        "tarball": "$HOST/$name/-/$name-$ver.tgz"
      }
    }
  }
}
EOF
}

# npm — NEGATIVE fixture: tarball host is foreign → gate must FAIL CLOSED (502).
build_npm_evil() { # name version
  local name="$1" ver="$2"
  mkdir -p "$WWW/npm"
  cat > "$WWW/npm/$name.json" <<EOF
{
  "name": "$name",
  "dist-tags": { "latest": "$ver" },
  "versions": {
    "$ver": {
      "name": "$name",
      "version": "$ver",
      "dist": {
        "shasum": "0000000000000000000000000000000000000000",
        "tarball": "https://evil.example.net/$name-$ver.tgz"
      }
    }
  }
}
EOF
}

# ---------------------------------------------------------------------------
# NuGet — clean package mycompany.nuget.lib@1.0.0
# ---------------------------------------------------------------------------
build_nuget() { # id version
  local id="$1" ver="$2" dir nupkg
  dir="$(mktemp -d)"
  cat > "$dir/$id.nuspec" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>$id</id>
    <version>$ver</version>
    <authors>shieldoo-e2e</authors>
    <description>E2E private NuGet multi-index fixture.</description>
  </metadata>
</package>
EOF
  cat > "$dir/[Content_Types].xml" <<'EOF'
<?xml version="1.0" encoding="utf-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="nuspec" ContentType="application/octet" />
  <Default Extension="xml" ContentType="application/xml" />
</Types>
EOF
  mkdir -p "$WWW/v3-flatcontainer/$id/$ver"
  nupkg="$WWW/v3-flatcontainer/$id/$ver/$id.$ver.nupkg"
  ( cd "$dir" && zip -q -X -r "$OLDPWD/$nupkg" "$id.nuspec" "[Content_Types].xml" )
  rm -rf "$dir"

  mkdir -p "$WWW/v3/registration/$id"
  cat > "$WWW/v3/registration/$id/index.json" <<EOF
{
  "count": 1,
  "items": [
    {
      "@id": "$HOST/v3/registration/$id/index.json#page",
      "count": 1,
      "items": [
        {
          "@id": "$HOST/v3/registration/$id/$ver.json",
          "packageContent": "$HOST/v3-flatcontainer/$id/$ver/$id.$ver.nupkg",
          "catalogEntry": {
            "id": "$id",
            "version": "$ver",
            "licenseExpression": "MIT",
            "licenseUrl": "https://licenses.example.org/MIT"
          }
        }
      ]
    }
  ]
}
EOF
}

# NuGet — NEGATIVE fixture: packageContent host is foreign → gate must FAIL CLOSED.
build_nuget_evil() { # id version
  local id="$1" ver="$2"
  mkdir -p "$WWW/v3/registration/$id"
  cat > "$WWW/v3/registration/$id/index.json" <<EOF
{
  "count": 1,
  "items": [
    {
      "@id": "$HOST/v3/registration/$id/index.json#page",
      "items": [
        { "packageContent": "https://evil.example.net/$id.$ver.nupkg",
          "catalogEntry": { "id": "$id", "version": "$ver" } }
      ]
    }
  ]
}
EOF
}

build_npm      mycompany-npm-lib  1.0.0
build_npm_evil mycompany-npm-evil 1.0.0
build_nuget      mycompany.nuget.lib  1.0.0
build_nuget_evil mycompany.nuget.evil 1.0.0
echo "Built npm + nuget fixtures under $WWW/"
