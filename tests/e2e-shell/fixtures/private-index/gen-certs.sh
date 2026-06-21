#!/usr/bin/env bash
# gen-certs.sh — regenerate the E2E private-index TLS material. Run once; commit outputs.
# TEST-ONLY self-signed CA + server cert for CN/SAN "private-index". NOT for production.
#
# Toolchain notes:
#   - Works on macOS LibreSSL 3.3.6 and Linux OpenSSL.
#   - Does NOT use process substitution (<(...)) for -extfile to remain POSIX-portable.
#     Instead, writes the extension to a temp file and removes it after signing.
set -euo pipefail
cd "$(dirname "$0")"

# Generate self-signed CA
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
  -keyout test-ca-key.pem -out test-ca.pem \
  -subj "/CN=shieldoo-e2e-private-index-CA"

# Generate server key + CSR
# -addext is supported by LibreSSL 3.3.6 and OpenSSL 1.1.1+; the SAN ends up in the
# CSR's extension request but we re-assert it explicitly on the signing step below,
# because the x509 command only copies extensions from the CSR if -copy_extensions copy
# is passed (not universally available). Writing an explicit extfile is safer.
openssl req -newkey rsa:2048 -nodes \
  -keyout server-key.pem -out server.csr \
  -subj "/CN=private-index"

# Sign: write SAN to a temp file so the approach is portable (no bash process substitution)
EXTFILE="$(mktemp)"
printf "subjectAltName=DNS:private-index" > "$EXTFILE"
openssl x509 -req -in server.csr -CA test-ca.pem -CAkey test-ca-key.pem \
  -CAcreateserial -days 3650 \
  -extfile "$EXTFILE" \
  -out server.pem
rm -f "$EXTFILE" server.csr test-ca.srl

# Verify SAN is present — Go's TLS requires SAN; a CN-only cert will NOT validate
echo "Verifying SAN in server.pem:"
openssl x509 -in server.pem -noout -text | grep -A1 "Subject Alternative Name"

echo "Generated test-ca.pem, test-ca-key.pem, server.pem, server-key.pem"
