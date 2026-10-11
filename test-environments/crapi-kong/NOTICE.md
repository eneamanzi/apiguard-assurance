# Third-party files in this lab

This lab runs OWASP crAPI (completely ridiculous API), https://github.com/OWASP/crAPI, licensed under the
Apache License 2.0 (https://www.apache.org/licenses/LICENSE-2.0). The following files are copies of crAPI files at
tag `v1.1.6` (commit `700f03d`), unmodified:

| File | crAPI source |
|---|---|
| `crapi-openapi-spec.json` | `openapi-spec/crapi-openapi-spec.json` |
| `keys/jwks.json` | `deploy/docker/keys/jwks.json` |

`docker-compose.yml` is derived from crAPI's `deploy/docker/docker-compose.yml` at the same tag (services reduced,
images pinned, passwords moved to `.env`, Kong added); the changes are described in its header.

crAPI is vulnerable by design. Run this lab only on a local machine, never exposed to a network.
