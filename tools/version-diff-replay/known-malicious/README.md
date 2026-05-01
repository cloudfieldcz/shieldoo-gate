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
