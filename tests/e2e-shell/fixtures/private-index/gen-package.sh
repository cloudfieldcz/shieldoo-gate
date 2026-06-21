#!/usr/bin/env bash
# gen-package.sh — build minimal sdists + PEP 503 simple pages for the E2E private index.
# Run once; commit the www/ tree.
#
# Toolchain notes:
#   - Does NOT use GNU tar --transform (not available on macOS bsdtar).
#     Instead, builds the name-version/ directory structure inside the temp dir directly
#     and tars that directory. This is POSIX-portable and produces the correct sdist
#     layout: name-version/pyproject.toml and name-version/name/__init__.py.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p www/packages www/simple

build_sdist() { # name version
  local name="$1" ver="$2"
  local tmpdir
  tmpdir="$(mktemp -d)"
  # Build the name-version/ directory layout directly — no GNU --transform needed
  mkdir -p "$tmpdir/$name-$ver/$name"
  printf 'def hello(): return "hi from %s"\n' "$name" > "$tmpdir/$name-$ver/$name/__init__.py"
  cat > "$tmpdir/$name-$ver/pyproject.toml" <<EOF
[project]
name = "$name"
version = "$ver"
EOF
  # tar the name-version/ subdirectory — works on bsdtar (macOS) and GNU tar (Linux)
  ( cd "$tmpdir" && tar czf "$name-$ver.tar.gz" "$name-$ver/" )
  cp "$tmpdir/$name-$ver.tar.gz" "www/packages/"
  rm -rf "$tmpdir"
}

simple_page() { # name version
  local name="$1" ver="$2"
  mkdir -p "www/simple/$name"
  cat > "www/simple/$name/index.html" <<EOF
<!DOCTYPE html><html><body>
<a href="../../packages/$name-$ver.tar.gz">$name-$ver.tar.gz</a>
</body></html>
EOF
}

# mycompany-lib: unscoped private package (served by 'private' index scope)
build_sdist mycompany-lib 1.0
simple_page mycompany-lib 1.0

# acme-widget: scoped package (served by 'corp' index scope)
build_sdist acme-widget 2.0
simple_page acme-widget 2.0

echo "Built www/ tree"
