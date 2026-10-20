#!/bin/sh
# test-environments/pki/gen-pki.sh
#
# The labs' certificate authority and the certificates it signs (LAB USE ONLY).
# Run by the one-shot "pki" service of every lab before its gateway starts
# (docs/04-architecture/05-design-decisions.md, D4); the folder is shared by the three
# labs, as one company authority signs every service.
#
#   ca.crt, ca.key          the lab authority (10 years)
#   server.crt, server.key  the gateways' certificate (180 days): names localhost,
#                           127.0.0.1, kong, apisix (the setup containers reach the
#                           gateways by service name)
#   client.crt, client.key  the tool's certificate for mutual TLS (180 days), CN apiguard
#
# Every certificate carries the RFC 5280 extensions strict validators require
# (basicConstraints, keyUsage, extendedKeyUsage, key identifiers).
#
# Idempotent: nothing is done when the files exist and are valid for 30 more
# days; certificates about to expire are reissued with the same authority; a
# missing or expiring authority regenerates everything. A lock makes two labs
# started together generate once. The files belong to the folder's owner (the
# user who cloned the repository); the private keys of the authority and of the
# client are readable only by them; the server key is readable by the gateways'
# users inside their containers (lab only).
#
# Usage (inside a container, the folder mounted at /pki):  sh /pki/gen-pki.sh
# To regenerate from scratch: delete the generated files and start a lab.

set -eu

PKI_DIR="${PKI_DIR:-/pki}"
LOCK_DIR="$PKI_DIR/.lock"
CA_DAYS=3650
LEAF_DAYS=180
RENEW_BEFORE_SECONDS=2592000   # 30 days
LOCK_WAIT_SECONDS=60
KEY_BITS=3072

cd "$PKI_DIR"

waited=0
until mkdir "$LOCK_DIR" 2>/dev/null; do
  if [ "$waited" -ge "$LOCK_WAIT_SECONDS" ]; then
    echo "gen-pki: lock $LOCK_DIR held for ${LOCK_WAIT_SECONDS}s; remove it if no lab is starting." >&2
    exit 1
  fi
  sleep 1
  waited=$((waited + 1))
done
trap 'rmdir "$LOCK_DIR"' EXIT

valid() {
  # $1: a certificate file; true when it exists and is valid for 30 more days.
  [ -f "$1" ] && openssl x509 -in "$1" -noout -checkend "$RENEW_BEFORE_SECONDS" >/dev/null 2>&1
}

cat > extensions.cnf <<'EOF'
[req]
distinguished_name = dn
prompt = no
[dn]
[ca]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
[server]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost, IP:127.0.0.1, DNS:kong, DNS:apisix
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
[client]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
EOF

issue() {
  # $1: name (server or client), $2: subject CN, $3: extension section.
  openssl req -new -newkey "rsa:$KEY_BITS" -nodes -keyout "$1.key" -out "$1.csr" \
    -subj "/O=APIGuard Lab/CN=$2" -config extensions.cnf 2>/dev/null
  openssl x509 -req -in "$1.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out "$1.crt" -days "$LEAF_DAYS" -sha256 -extfile extensions.cnf -extensions "$3" 2>/dev/null
  rm -f "$1.csr"
  echo "gen-pki: issued $1.crt (CN $2, $LEAF_DAYS days)."
}

changed=no
if ! valid ca.crt || [ ! -f ca.key ]; then
  openssl req -x509 -newkey "rsa:$KEY_BITS" -nodes -keyout ca.key -out ca.crt -days "$CA_DAYS" \
    -sha256 -subj "/O=APIGuard Lab/CN=APIGuard Lab CA" -config extensions.cnf -extensions ca 2>/dev/null
  rm -f server.crt client.crt ca.srl
  echo "gen-pki: created the lab authority ca.crt ($CA_DAYS days)."
  changed=yes
fi
if ! valid server.crt || [ ! -f server.key ]; then
  issue server localhost server
  changed=yes
fi
if ! valid client.crt || [ ! -f client.key ]; then
  issue client apiguard client
  changed=yes
fi

owner="$(stat -c '%u:%g' "$PKI_DIR")"
chown "$owner" ca.crt ca.key server.crt server.key client.crt client.key extensions.cnf
[ -f ca.srl ] && chown "$owner" ca.srl
chmod 644 ca.crt server.crt client.crt server.key extensions.cnf
chmod 600 ca.key client.key

if [ "$changed" = no ]; then
  echo "gen-pki: certificates present and valid; nothing to do."
fi
