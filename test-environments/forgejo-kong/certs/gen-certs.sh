#!/usr/bin/env bash
# test-environments/forgejo-kong/certs/gen-certs.sh
#
# Generates a self-signed TLS certificate and private key for the Kong lab
# environment.  The certificate covers localhost and 127.0.0.1 via Subject
# Alternative Names (SAN), which is required by modern TLS implementations
# (RFC 6125 deprecates CN-only matching).
#
# Output files (written to the same directory as this script):
#   server.crt  -- PEM-encoded X.509 certificate (2048-bit RSA, 825-day validity)
#   server.key  -- PEM-encoded RSA private key
#
# Usage:
#   cd test-environments/forgejo-kong/certs
#   chmod +x gen-certs.sh
#   ./gen-certs.sh
#
# The generated files are mounted read-only into the Kong container via the
# docker-compose.yml volume: ./certs:/etc/kong/certs:ro
#
# IMPORTANT: This certificate is for LOCAL LAB USE ONLY.
# - It is self-signed (not issued by a trusted CA).
# - The tool must be configured with verify_tls: false in config.yaml.
# - Never use a self-signed certificate in a production environment.
#
# Both files are already in .gitignore (*.crt, *.key).
# Do NOT commit private keys to version control.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT_FILE="${SCRIPT_DIR}/server.crt"
KEY_FILE="${SCRIPT_DIR}/server.key"
VALIDITY_DAYS=825     # 825 days = ~2 years + 3 months (max for self-signed by browser policy)
KEY_BITS=2048

echo "[gen-certs] Generating ${KEY_BITS}-bit RSA key and self-signed certificate..."
echo "[gen-certs] Output: ${CERT_FILE}"
echo "[gen-certs]         ${KEY_FILE}"

openssl req -x509 \
    -newkey rsa:${KEY_BITS} \
    -keyout "${KEY_FILE}" \
    -out "${CERT_FILE}" \
    -days ${VALIDITY_DAYS} \
    -nodes \
    -subj "/C=IT/ST=Liguria/L=Genova/O=Thesis Lab/OU=API Security/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

echo "[gen-certs] Certificate generated successfully."
echo ""
echo "  Subject:  $(openssl x509 -noout -subject -in "${CERT_FILE}")"
echo "  Expires:  $(openssl x509 -noout -enddate -in "${CERT_FILE}")"
echo "  SAN:      $(openssl x509 -noout -ext subjectAltName -in "${CERT_FILE}" 2>/dev/null | tail -1)"
echo ""
echo "[gen-certs] REMINDER: Set verify_tls: false in config.yaml for lab use."

# Lab only: relax permissions so the Kong container process (non-root)
# can read the key. In production, use a secrets manager instead.
# chmod 644 server.key server.crt