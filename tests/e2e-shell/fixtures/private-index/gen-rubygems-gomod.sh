#!/usr/bin/env bash
# gen-rubygems-gomod.sh — build minimal RubyGems + Go-module private-index
# fixtures into www/. Run once; commit the generated artifacts. Mirrors
# gen-npm-nuget.sh.
#
# Layout produced (served by the shared private-index Caddy at https://private-index:8443):
#   rubygems gem:          www/gems/<name>-<ver>.gem
#   rubygems gem JSON:     www/api/v1/gems/<name>.json   (gem_uri → HOST/gems/...)
#   rubygems compact info: www/info/<name>               (modern Bundler/gem path)
#   gomod list/info/mod:   www/<module>/@v/...
#   gomod zip:             www/<module>/@v/<ver>.zip      (module@ver/ prefixed)
#
# The gem_uri download URL points at https://private-index:8443 WITHOUT a path
# prefix so that, after the gate rewrites it to its own origin, it routes back to
# the gate's own /gems/ scanned route. GOPROXY metadata has no download URLs.
set -euo pipefail
cd "$(dirname "$0")"
WWW="www"
HOST="https://private-index:8443"

# ---------------------------------------------------------------------------
# RubyGems — clean gem mycompany-gem@1.0.0
# ---------------------------------------------------------------------------
build_gem() { # name version
  local name="$1" ver="$2" dir gem sha256
  dir="$(mktemp -d)"
  mkdir -p "$dir/lib"
  printf 'module MycompanyGem\n  VERSION = "%s"\nend\n' "$ver" > "$dir/lib/mycompany_gem.rb"
  cat > "$dir/$name.gemspec" <<EOF
Gem::Specification.new do |s|
  s.name        = "$name"
  s.version     = "$ver"
  s.summary     = "E2E private RubyGems multi-index fixture."
  s.authors     = ["shieldoo-e2e"]
  s.files       = ["lib/mycompany_gem.rb"]
  s.license     = "MIT"
end
EOF
  ( cd "$dir" && gem build "$name.gemspec" --output "$name-$ver.gem" >/dev/null )
  mkdir -p "$WWW/gems"
  gem="$WWW/gems/$name-$ver.gem"
  cp "$dir/$name-$ver.gem" "$gem"
  rm -rf "$dir"
  sha256="$(openssl dgst -sha256 "$gem" | awk '{print $2}')"

  # /api/v1/gems/<name>.json — gem_uri is the single download field (rewritten).
  mkdir -p "$WWW/api/v1/gems"
  cat > "$WWW/api/v1/gems/$name.json" <<EOF
{
  "name": "$name",
  "version": "$ver",
  "platform": "ruby",
  "gem_uri": "$HOST/gems/$name-$ver.gem",
  "homepage_uri": "https://corp.example.com/$name",
  "sha": "$sha256",
  "licenses": ["MIT"]
}
EOF

  # Compact index /info/<name> (modern Bundler/gem) — checksum, NO download URL.
  mkdir -p "$WWW/info"
  cat > "$WWW/info/$name" <<EOF
---
$ver |checksum:$sha256
EOF
}

# RubyGems — NEGATIVE fixture: gem_uri host is foreign → gate must FAIL CLOSED (502).
build_gem_evil() { # name version
  local name="$1" ver="$2"
  mkdir -p "$WWW/api/v1/gems"
  cat > "$WWW/api/v1/gems/$name.json" <<EOF
{
  "name": "$name",
  "version": "$ver",
  "gem_uri": "https://evil.example.net/gems/$name-$ver.gem",
  "licenses": ["MIT"]
}
EOF
  mkdir -p "$WWW/info"
  cat > "$WWW/info/$name" <<EOF
---
$ver |checksum:0000000000000000000000000000000000000000000000000000000000000000
EOF
}

# ---------------------------------------------------------------------------
# Go modules — clean module github.com/mycompany/lib@v1.0.0
# ---------------------------------------------------------------------------
build_gomod() { # module version
  local module="$1" ver="$2" dir vdir prefix
  dir="$(mktemp -d)"
  prefix="$module@$ver"
  vdir="$dir/$prefix"
  mkdir -p "$vdir"
  cat > "$vdir/go.mod" <<EOF
module $module

go 1.21
EOF
  printf 'package lib\n\n// Hello is an E2E private-module fixture.\nfunc Hello() string { return "hi from %s" }\n' "$module" > "$vdir/lib.go"
  cat > "$vdir/LICENSE" <<'EOF'
MIT License

Copyright (c) 2026 shieldoo-e2e

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction.
EOF

  mkdir -p "$WWW/$module/@v"
  # GOPROXY metadata
  printf '%s\n' "$ver" > "$WWW/$module/@v/list"
  cat > "$WWW/$module/@v/$ver.info" <<EOF
{"Version":"$ver","Time":"2026-01-01T00:00:00Z"}
EOF
  cp "$vdir/go.mod" "$WWW/$module/@v/$ver.mod"
  # Module zip: every entry prefixed module@version/
  ( cd "$dir" && zip -q -X -r "$OLDPWD/$WWW/$module/@v/$ver.zip" "$prefix" )
  rm -rf "$dir"
}

build_gem       mycompany-gem  1.0.0
build_gem_evil  mycompany-evil 1.0.0
build_gomod     github.com/mycompany/lib v1.0.0
echo "Built rubygems + gomod fixtures under $WWW/"
