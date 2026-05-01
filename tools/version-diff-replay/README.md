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
