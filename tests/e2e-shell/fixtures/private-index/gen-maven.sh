#!/usr/bin/env bash
# gen-maven.sh — build a minimal Maven private-index fixture into www/maven/.
# Run once; commit the generated artifacts. Mirrors gen-rubygems-gomod.sh.
#
# Layout produced (served by the shared private-index Caddy at
# https://private-index:8443/maven — the index `url` in config.e2e.yaml):
#   POM:        www/maven/<groupPath>/<artifactId>/<ver>/<artifactId>-<ver>.pom
#   JAR:        www/maven/<groupPath>/<artifactId>/<ver>/<artifactId>-<ver>.jar
#   JAR sha1:   www/maven/<groupPath>/<artifactId>/<ver>/<artifactId>-<ver>.jar.sha1
#   metadata:   www/maven/<groupPath>/<artifactId>/maven-metadata.xml
#
# Maven embeds no download URLs in metadata (clients construct artifact URLs from
# the coordinate), so there is no rewrite surface and no foreign-host negative
# fixture — the scoped-miss + namespacing are the security assertions.
set -euo pipefail
cd "$(dirname "$0")"
WWW="www"

build_maven() { # groupId artifactId version
  local group="$1" artifact="$2" ver="$3"
  local groupPath dir base
  groupPath="$(printf '%s' "$group" | tr '.' '/')"
  dir="$WWW/maven/$groupPath/$artifact/$ver"
  mkdir -p "$dir"
  base="$artifact-$ver"

  # POM with an explicit <licenses> block so the effective-POM resolver enriches.
  cat > "$dir/$base.pom" <<EOF
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>$group</groupId>
  <artifactId>$artifact</artifactId>
  <version>$ver</version>
  <licenses><license><name>Apache-2.0</name></license></licenses>
</project>
EOF

  # JAR: a real (tiny) zip — Trivy is not registered in this E2E, so the content
  # is not deeply inspected; it only needs to be a valid downloadable artifact.
  local jdir
  jdir="$(mktemp -d)"
  printf 'private maven multi-index fixture: %s:%s:%s\n' "$group" "$artifact" "$ver" > "$jdir/README.txt"
  ( cd "$jdir" && zip -q -X "$OLDPWD/$dir/$base.jar" README.txt )
  rm -rf "$jdir"
  ( cd "$dir" && sha1sum "$base.jar" | cut -d' ' -f1 > "$base.jar.sha1" )

  # Artifact-level maven-metadata.xml (version listing).
  cat > "$WWW/maven/$groupPath/$artifact/maven-metadata.xml" <<EOF
<metadata>
  <groupId>$group</groupId>
  <artifactId>$artifact</artifactId>
  <versioning>
    <latest>$ver</latest>
    <release>$ver</release>
    <versions><version>$ver</version></versions>
  </versioning>
</metadata>
EOF
}

build_maven com.mycompany lib 1.0.0
echo "Built maven fixture under $WWW/maven/"
