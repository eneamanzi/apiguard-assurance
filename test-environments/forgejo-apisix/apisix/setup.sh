#!/bin/sh
# test-environments/forgejo-apisix/apisix/setup.sh
#
# Writes the gateway configuration of the Forgejo + APISIX lab through the APISIX Admin API.
# It is the counterpart of kong/kong.yml in the Forgejo + Kong lab, with the same intent: APISIX
# with etcd starts with no routes, and its configuration is written through the Admin API.
#
# Run by the apisix-setup service of docker-compose.yml (image curlimages/curl), which starts only
# when APISIX is ready (its health check, GET /status/ready), with:
#   APISIX_ADMIN_KEY  the key with role admin (from .env); the tool uses the viewer key instead;
#   /pki              the labs' authority and certificates (test-environments/pki), read only.
#
# The Admin API is HTTPS with mutual TLS (apisix/config.yaml): the setup verifies APISIX's
# certificate with the labs' authority and presents the client certificate, then the admin key.
#
# Every object is written with PUT and a fixed id: running the setup again rewrites the same
# objects with the same values. Any answer other than HTTP 200/201 stops the setup.
#
# Fields checked against the APISIX 3.19.0 sources (apisix/schema_def.lua and the plugins in
# apisix/plugins/); the Admin API reference: https://apisix.apache.org/docs/apisix/admin-api/

set -eu

ADMIN_URL="https://apisix:10001/apisix/admin"
PKI="/pki"
: "${APISIX_ADMIN_KEY:?APISIX_ADMIN_KEY is not set - see .env.example}"

# put <path> <json body>: writes one object, stops on an unexpected answer.
put() {
  code=$(curl -s -o /tmp/apisix_response -w '%{http_code}' -X PUT "$ADMIN_URL/$1" \
    --cacert "$PKI/ca.crt" --cert "$PKI/client.crt" --key "$PKI/client.key" \
    -H "X-API-KEY: $APISIX_ADMIN_KEY" -H 'Content-Type: application/json' -d "$2")
  case "$code" in
    200|201) echo "APISIX $1 written." ;;
    *) echo "APISIX $1 failed: HTTP $code"; cat /tmp/apisix_response; echo; exit 1 ;;
  esac
}

# PEM file as one JSON string: each line ends with an escaped newline (PEM text has no quotes
# or backslashes to escape).
pem_json() {
  awk 'BEGIN { ORS = "\\n" } { print }' "$1"
}

# --- TLS certificate for the HTTPS proxy (10443): the lab certificate --------------------------
put "ssls/localhost" "{
  \"cert\": \"$(pem_json "$PKI/server.crt")\",
  \"key\": \"$(pem_json "$PKI/server.key")\",
  \"snis\": [\"localhost\"]
}"

# --- Forgejo backend: timeouts and health checks ------------------------------------------------
# Timeouts in seconds, the same as the Kong lab service (5 s connect, 30 s send and read).
# Passive checks: the same thresholds as the Kong lab. Active checks re-enable an excluded node
# (passive checks alone never do). APISIX requires an interval of at least 1 s for healthy nodes
# too, so healthy nodes are probed every 60 s, where Kong probes none (healthy.interval 0).
put "upstreams/forgejo-upstream" '{
  "name": "forgejo-upstream",
  "type": "roundrobin",
  "nodes": { "forgejo:3000": 100 },
  "timeout": { "connect": 5, "send": 30, "read": 30 },
  "checks": {
    "active": {
      "type": "http",
      "http_path": "/api/healthz",
      "healthy": { "interval": 60, "successes": 1 },
      "unhealthy": { "interval": 5 }
    },
    "passive": {
      "type": "http",
      "healthy": { "successes": 2 },
      "unhealthy": {
        "http_failures": 5,
        "timeouts": 3,
        "http_statuses": [500, 502, 503, 504]
      }
    }
  }
}'

# --- Forgejo API route -------------------------------------------------------------------------
# HTTP requests get a redirect to the same path over HTTPS (301 for GET and HEAD, 308 for other
# methods); a path that no route matches gets APISIX's 404 on both listeners.
# Security headers as in the Kong lab; "set" writes each header whether or not Forgejo sent it.
put "routes/forgejo-api-route" '{
  "name": "forgejo-api-route",
  "uris": ["/api", "/api/*"],
  "upstream_id": "forgejo-upstream",
  "plugins": {
    "redirect": { "http_to_https": true },
    "response-rewrite": {
      "headers": {
        "set": {
          "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
          "Content-Security-Policy": "default-src '"'"'self'"'"'",
          "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
          "X-Content-Type-Options": "nosniff",
          "X-Frame-Options": "DENY"
        },
        "remove": ["X-Powered-By"]
      }
    }
  }
}'

# --- Forgejo OpenAPI specification route ------------------------------------------------------
# The only path outside /api (the tool downloads the specification from here: Forgejo publishes no
# port); "uri" without "*" matches exactly. Same plugins as the API route.
put "routes/forgejo-spec-route" '{
  "name": "forgejo-spec-route",
  "uri": "/swagger.v1.json",
  "upstream_id": "forgejo-upstream",
  "plugins": {
    "redirect": { "http_to_https": true },
    "response-rewrite": {
      "headers": {
        "set": {
          "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
          "Content-Security-Policy": "default-src '"'"'self'"'"'",
          "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
          "X-Content-Type-Options": "nosniff",
          "X-Frame-Options": "DENY"
        },
        "remove": ["X-Powered-By"]
      }
    }
  }
}'

# --- Route used only by the test 3.3 HMAC audit --------------------------------------------------
# hmac-auth on a path no client uses, so that the Bearer-token traffic of the other tests is not
# rejected; test 3.3 reads its configuration through the Admin API. APISIX 3.19.0 accepts
# hmac-sha1, hmac-sha256 and hmac-sha512 (no hmac-sha384) and allows all three by default.
# To produce FAIL findings: add "hmac-sha1" to allowed_algorithms, or set clock_skew above 300.
put "routes/hmac-audit-route" '{
  "name": "hmac-audit-route",
  "uri": "/hmac-audit-probe-not-a-real-path",
  "upstream_id": "forgejo-upstream",
  "plugins": {
    "hmac-auth": {
      "allowed_algorithms": ["hmac-sha256", "hmac-sha512"],
      "clock_skew": 300,
      "validate_request_body": true
    }
  }
}'

echo "APISIX configuration completed."
