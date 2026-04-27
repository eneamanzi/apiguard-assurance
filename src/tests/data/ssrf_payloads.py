"""
src/tests/data/ssrf_payloads.py

SSRF attack payload catalogue for test 7.2.

This module is pure data: it defines no functions and performs no I/O.

Sources
-------
Every payload entry is traceable to at least one of the following primary
sources:

1. PayloadsAllTheThings — swisskyrepo/PayloadsAllTheThings, section
   "Server Side Request Forgery" (MIT licence).
   URL: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery

2. OWASP Web Security Testing Guide v4.2 — WSTG-INPV-19: Testing for
   Server-Side Request Forgery.
   URL: https://owasp.org/www-project-web-security-testing-guide/

3. OWASP API Security Testing Guide — OWASP API7:2023.
   URL: https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/

4. Orange Tsai — "A New Era of SSRF — Exploiting URL Parser in Trending
   Middleware Blindly" (BlackHat USA 2017).
   URL: https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Middleware-Blindly.pdf

5. AWS documentation — Instance Metadata Service (IMDSv1/v2), ECS Task
   Metadata Endpoint.
   URL: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html
        https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-metadata-endpoint.html

6. NIST SP 800-204 Section 3.2.2 — Microservices-based Systems Security.

7. RFC 3986 — Uniform Resource Identifier (URI): Generic Syntax.
   Defines which notation forms are equivalent for IP literals.

Structure
---------
Each payload entry is a 3-tuple (url, description, category) where:
    url         -- The URL string to submit as user-controlled input.
    description -- Short human-readable label for the HTML Audit Trail and
                   Finding.detail. Must be self-explanatory without context.
    category    -- Matches one of the category strings consumed by test 7.2
                   via cfg.payload_categories.

Categories
----------
    cloud_metadata        Cloud provider IMDS endpoints (AWS EC2, AWS ECS,
                          GCP, Azure, DigitalOcean).
                          Source: AWS docs [5], PayloadsAllTheThings [1].
    private_ip            RFC-1918 / loopback / link-local ranges.
                          Source: PayloadsAllTheThings [1], OWASP WSTG [2].
    encoding_bypass       Obfuscated representations of loopback and cloud
                          metadata IPs: decimal integer, hex, octal, abbreviated
                          dotted, IPv4-mapped IPv6, IPv6 full/compressed,
                          URL-encoded, double URL-encoded, mixed-case hostname.
                          Source: PayloadsAllTheThings [1], Orange Tsai [4],
                          RFC 3986 [7].
    forbidden_protocol    Non-HTTP protocol scheme URLs.
                          Source: PayloadsAllTheThings [1], OWASP WSTG [2].
    dns_bypass            Public wildcard DNS hostnames that resolve to private
                          IPs (nip.io, sslip.io). Tests DNS-name-based blacklist
                          bypass. Source: PayloadsAllTheThings [1].
    url_parser_confusion  Authority component ambiguity exploits (@ symbol,
                          backslash, embedded credentials) that cause
                          frontend/backend URL parser disagreement.
                          Source: Orange Tsai [4], PayloadsAllTheThings [1].

Dependency rule
---------------
This module has no imports. It is a data file only.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Category A -- Cloud metadata endpoints
#
# Sources: AWS documentation [5], PayloadsAllTheThings [1], OWASP WSTG [2].
# 169.254.169.254 is the link-local address reserved for IMDS across AWS,
# GCP, Azure, and DigitalOcean.
# The AWS ECS task metadata endpoint (169.254.170.2) is distinct from EC2
# IMDS and exposes temporary IAM credentials for the ECS task execution role.
# ---------------------------------------------------------------------------

CLOUD_METADATA_URLS: tuple[tuple[str, str], ...] = (
    # -- AWS IMDSv1 (unauthenticated, highest risk) --
    # Source: AWS EC2 User Guide [5]
    ("http://169.254.169.254/latest/meta-data/", "AWS IMDSv1 root"),
    (
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "AWS IAM credentials via IMDSv1",
    ),
    ("http://169.254.169.254/latest/meta-data/hostname", "AWS EC2 hostname via IMDS"),
    ("http://169.254.169.254/latest/user-data", "AWS EC2 user-data (may contain secrets)"),
    # -- AWS ECS task metadata endpoint --
    # Source: AWS ECS documentation [5].
    # Distinct address (169.254.170.2) used only in Fargate/ECS environments.
    ("http://169.254.170.2/v2/credentials/", "AWS ECS task metadata credentials root"),
    # -- GCP metadata server --
    # Source: PayloadsAllTheThings [1]
    (
        "http://metadata.google.internal/computeMetadata/v1/",
        "GCP metadata via DNS hostname",
    ),
    ("http://169.254.169.254/computeMetadata/v1/", "GCP metadata via link-local IP"),
    (
        "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token",
        "GCP service account OAuth2 token",
    ),
    # -- Azure IMDS --
    # Source: PayloadsAllTheThings [1]
    ("http://169.254.169.254/metadata/instance", "Azure IMDS instance metadata"),
    (
        "http://169.254.169.254/metadata/identity/oauth2/token",
        "Azure managed identity OAuth2 token",
    ),
    # -- DigitalOcean --
    # Source: PayloadsAllTheThings [1]
    ("http://169.254.169.254/metadata/v1/", "DigitalOcean droplet metadata root"),
)

# ---------------------------------------------------------------------------
# Category B -- Private IP ranges (RFC-1918, loopback, link-local)
#
# Sources: PayloadsAllTheThings [1], OWASP WSTG WSTG-INPV-19 [2].
# RFC 1918 blocks: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16.
# Loopback: 127.0.0.0/8.  Link-local: 169.254.0.0/16.
# ---------------------------------------------------------------------------

PRIVATE_IP_URLS: tuple[tuple[str, str], ...] = (
    # -- Loopback --
    ("http://127.0.0.1", "IPv4 loopback"),
    ("http://127.0.0.1:8080", "IPv4 loopback with port"),
    ("http://localhost", "localhost hostname"),
    ("http://localhost:8080", "localhost with port"),
    # -- Unspecified / wildcard listener addresses --
    # Source: PayloadsAllTheThings [1], RFC 1122 Section 3.2.1.3,
    #         RFC 4291 Section 2.5.2.
    # 0.0.0.0 is the IPv4 "any" address (INADDR_ANY). Many OS TCP stacks
    # route HTTP requests targeting 0.0.0.0 to 127.0.0.1 or to the first
    # available local interface. Applications bound to 0.0.0.0 (wildcard
    # listener) are therefore reachable via this address on the same host.
    # A string-matching blacklist for "127.0.0.1" does not block "0.0.0.0".
    # [::] is the IPv6 equivalent of 0.0.0.0 (IN6ADDR_ANY). Servers bound
    # to [::] accept connections on all interfaces including loopback.
    # A blacklist blocking [::1] (IPv6 loopback) but not [::] misses this.
    # Correct mitigation: resolve the URL to a final IP and validate it
    # against the full set of private/loopback/unspecified CIDR ranges.
    ("http://0.0.0.0", "IPv4 unspecified address (resolves to loopback on most stacks)"),
    ("http://0.0.0.0:8080", "IPv4 unspecified address with port"),
    ("http://[::]", "IPv6 unspecified address IN6ADDR_ANY (equivalent of 0.0.0.0)"),
    ("http://[::]:8080", "IPv6 unspecified address with port"),
    # -- RFC-1918 Class A (10.0.0.0/8) --
    ("http://10.0.0.1", "RFC-1918 class A"),
    ("http://10.0.0.1:8080/admin", "RFC-1918 class A admin path"),
    ("http://10.255.255.255", "RFC-1918 class A upper bound"),
    # -- RFC-1918 Class B (172.16.0.0/12) --
    ("http://172.16.0.1", "RFC-1918 class B lower bound"),
    ("http://172.31.255.255", "RFC-1918 class B upper bound"),
    # -- RFC-1918 Class C (192.168.0.0/16) --
    ("http://192.168.1.1", "RFC-1918 class C"),
    ("http://192.168.0.1", "RFC-1918 class C gateway"),
    # -- Link-local / APIPA --
    ("http://169.254.1.1", "link-local APIPA range"),
)

# ---------------------------------------------------------------------------
# Category C -- Encoding bypass variants
#
# Sources: PayloadsAllTheThings [1], Orange Tsai BlackHat USA 2017 [4],
#          RFC 3986 Section 3.2.2 [7].
#
# These represent the same IP addresses in non-canonical notation.
# A string-matching blacklist (e.g. 'if "127.0.0.1" in url') fails to block
# them.  A correct implementation resolves the URL to a final IP and checks
# the resolved address.
#
# Cloud metadata IP encoding:
#   169.254.169.254 as decimal = 2852039166
#   169.254.169.254 as hex     = 0xA9FEA9FE
#   AWS IMDSv2 IPv6 alternative: fd00:ec2::254 (AWS-documented, source [5])
#
# 127.0.0.1 encoding:
#   decimal = 2130706433
#   hex     = 0x7f000001
#   octal   = 0177.0.0.1
# ---------------------------------------------------------------------------

ENCODING_BYPASS_URLS: tuple[tuple[str, str], ...] = (
    # -- 127.0.0.1 integer encoding --
    # Source: PayloadsAllTheThings [1], RFC 3986 [7]
    ("http://2130706433", "127.0.0.1 as decimal integer"),
    ("http://0x7f000001", "127.0.0.1 as hex integer"),
    ("http://0177.0.0.1", "127.0.0.1 as octal dotted"),
    # -- 127.0.0.1 abbreviated dotted notation --
    # Source: PayloadsAllTheThings [1]
    ("http://127.1", "127.1 two-part abbreviated loopback"),
    ("http://127.0.1", "127.0.1 three-part abbreviated loopback"),
    # -- Extended loopback range (full 127.0.0.0/8 is reserved, RFC 3330) --
    # Source: PayloadsAllTheThings [1]
    ("http://127.127.127.127", "loopback range 127.x.x.x variant"),
    ("http://127.0.0.0", "loopback range lower bound"),
    # -- 127.0.0.1 IPv6 variants --
    # Source: Orange Tsai [4], RFC 3986 [7]
    ("http://[::1]", "IPv6 loopback compressed"),
    ("http://[::1]:8080", "IPv6 loopback with port"),
    ("http://[0:0:0:0:0:0:0:1]", "IPv6 loopback full form"),
    ("http://[::ffff:127.0.0.1]", "IPv4-mapped IPv6 loopback (::ffff:127.0.0.1)"),
    ("http://[::ffff:7f00:1]", "IPv4-mapped IPv6 loopback hex form (::ffff:7f00:1)"),
    # -- 127.0.0.1 URL-encoded host (expect SSRF_BLOCKED_AS_MALFORMED_URL) --
    # Go's net/url rejects percent-encoded octets in the host (RFC 3986 S3.2.2).
    # These trigger parser-level rejection, not SSRF-aware validation.
    # Source: PayloadsAllTheThings [1]
    ("http://%31%32%37%2e%30%2e%30%2e%31", "127.0.0.1 URL-encoded host"),
    (
        "http://%2531%2532%2537%252e%2530%252e%2530%252e%2531",
        "127.0.0.1 double URL-encoded host",
    ),
    # -- Hostname case variants --
    # Source: PayloadsAllTheThings [1]
    ("http://Localhost", "localhost mixed case"),
    ("http://LOCALHOST", "localhost uppercase"),
    # -- Cloud metadata IP (169.254.169.254) encoding variants --
    # Source: PayloadsAllTheThings [1], AWS documentation [5]
    ("http://2852039166", "169.254.169.254 as decimal integer"),
    ("http://0xA9FEA9FE", "169.254.169.254 as hex integer"),
    ("http://[::ffff:169.254.169.254]", "169.254.169.254 IPv4-mapped IPv6"),
    ("http://[::ffff:a9fe:a9fe]", "169.254.169.254 IPv4-mapped IPv6 hex form"),
    # AWS-documented IPv6 alternative for IMDSv2 within VPC -- source [5].
    ("http://[fd00:ec2::254]", "AWS IMDSv2 IPv6 alternative (fd00:ec2::254)"),
)

# ---------------------------------------------------------------------------
# Category D -- Forbidden protocol schemes
#
# Sources: PayloadsAllTheThings [1], OWASP WSTG WSTG-INPV-19 [2].
# ---------------------------------------------------------------------------

FORBIDDEN_PROTOCOL_URLS: tuple[tuple[str, str], ...] = (
    ("file:///etc/passwd", "file:// to /etc/passwd"),
    ("file:///etc/hosts", "file:// to /etc/hosts"),
    ("file:///proc/self/environ", "file:// to /proc/self/environ"),
    ("file:///etc/shadow", "file:// to /etc/shadow"),
    ("gopher://127.0.0.1:25/", "gopher:// SMTP relay"),
    ("gopher://127.0.0.1:6379/_PING", "gopher:// Redis PING"),
    ("dict://127.0.0.1:11211/", "dict:// memcached"),
    ("ftp://127.0.0.1/", "ftp:// loopback"),
    ("ldap://127.0.0.1:389/", "ldap:// loopback"),
    ("tftp://127.0.0.1:69/", "tftp:// loopback"),
    ("sftp://127.0.0.1/", "sftp:// loopback"),
    ("netdoc:///etc/passwd", "netdoc:// Java-specific scheme"),
)

# ---------------------------------------------------------------------------
# Category E -- DNS-based bypass (nip.io / sslip.io)
#
# Source: PayloadsAllTheThings [1].
#
# nip.io and sslip.io are public wildcard DNS services: any hostname of the
# form <ip>.nip.io resolves to the encoded IP.  A string-matching blacklist
# fails to detect these; a correct defence must resolve the hostname and
# validate the resolved IP.
# ---------------------------------------------------------------------------

DNS_BYPASS_URLS: tuple[tuple[str, str], ...] = (
    ("http://127.0.0.1.nip.io", "loopback via nip.io wildcard DNS"),
    ("http://127.0.0.1.nip.io:8080", "loopback via nip.io with port"),
    ("http://169.254.169.254.nip.io", "cloud IMDS via nip.io wildcard DNS"),
    ("http://10.0.0.1.nip.io", "RFC-1918 class A via nip.io"),
    ("http://192.168.1.1.nip.io", "RFC-1918 class C via nip.io"),
    ("http://127.0.0.1.sslip.io", "loopback via sslip.io wildcard DNS"),
    ("http://169.254.169.254.sslip.io", "cloud IMDS via sslip.io wildcard DNS"),
)

# ---------------------------------------------------------------------------
# Category F -- URL parser confusion (authority component ambiguity)
#
# Source: Orange Tsai BlackHat USA 2017 [4], PayloadsAllTheThings [1].
#
# The @ symbol separates userinfo from host in RFC 3986:
#   http://userinfo@host/path
# Different parsers may disagree on which part is the host.  If the frontend
# validates based on "safe.example.com" but the backend connects to
# "127.0.0.1", the SSRF check is bypassed.
#
# These payloads use 'safe.example.com' as a placeholder for the allowed
# domain.  Replace with a real allowed domain when testing applications that
# implement a domain allow-list.
# ---------------------------------------------------------------------------

URL_PARSER_CONFUSION_URLS: tuple[tuple[str, str], ...] = (
    # Source: Orange Tsai [4] -- @ authority ambiguity
    (
        "http://safe.example.com@127.0.0.1/",
        "@ ambiguity: userinfo=safe.example.com host=127.0.0.1",
    ),
    (
        "http://safe.example.com@169.254.169.254/",
        "@ ambiguity: userinfo=safe.example.com host=IMDS",
    ),
    # Source: Orange Tsai [4] -- backslash normalization
    (
        "http://safe.example.com\\@127.0.0.1/",
        "backslash @ ambiguity: true host may be 127.0.0.1",
    ),
    # Source: PayloadsAllTheThings [1] -- embedded credentials
    (
        "http://user:password@127.0.0.1/",
        "embedded credentials: host is 127.0.0.1",
    ),
    (
        "http://user:password@169.254.169.254/latest/meta-data/",
        "embedded credentials: host is cloud IMDS",
    ),
    # Source: Orange Tsai [4] -- port backslash @ confusion
    (
        "http://127.0.0.1:80\\@169.254.169.254/",
        "port backslash @ ambiguity: true target is cloud IMDS",
    ),
)

# ---------------------------------------------------------------------------
# Open redirect / SSRF via redirect chain
#
# Methodology ref: Garanzia 7.2 -- Redirect Following Validation.
# The consuming test substitutes the operator-controlled redirect server URL
# at runtime via cfg.ssrf_redirect_server_url.  This sentinel documents the
# attack pattern without embedding a runtime URL.
# ---------------------------------------------------------------------------

REDIRECT_SSRF_SENTINEL: str = "REQUIRES_REDIRECT_SERVER"

# ---------------------------------------------------------------------------
# Aggregated catalogue
#
# ALL_SSRF_PAYLOADS is the complete set iterated by test 7.2.
# Each entry: (url, description, category).
# The category string must exactly match the values in cfg.payload_categories.
# ---------------------------------------------------------------------------

ALL_SSRF_PAYLOADS: tuple[tuple[str, str, str], ...] = (
    *((url, desc, "cloud_metadata") for url, desc in CLOUD_METADATA_URLS),
    *((url, desc, "private_ip") for url, desc in PRIVATE_IP_URLS),
    *((url, desc, "encoding_bypass") for url, desc in ENCODING_BYPASS_URLS),
    *((url, desc, "forbidden_protocol") for url, desc in FORBIDDEN_PROTOCOL_URLS),
    *((url, desc, "dns_bypass") for url, desc in DNS_BYPASS_URLS),
    *((url, desc, "url_parser_confusion") for url, desc in URL_PARSER_CONFUSION_URLS),
)
