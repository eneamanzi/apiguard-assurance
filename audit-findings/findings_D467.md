# Findings D467 (saved by main from the agent's text reply; condensed)

Counts: 5 High, 9 Medium, 11 Low, 1 Info. No lab requests; sources: NIST SP 800-204/204A PDFs, Kong handler PRIORITY values, APISIX limit-count docs.

- D467-1 High CONFIRMED crAPI: 7.2's first three cloud-metadata payloads hang 30 s -> Kong 504 x3 -> passive healthcheck unhealthy.timeouts: 3 (crapi-kong/kong/kong.yml:92-98) -> workshop 503 ring-balancer for rest of 7.2 (70 payloads), 0.1_103+, 4.1_001-003, 4.4_001, 7.3_002-016. Pages 4.1/4.4/7.3 and comment test_7_3:273-275 blame load/race. The 504s are the blind-SSRF timing signal but labelled UPSTREAM_UNAVAILABLE. Production risk: 7.2 can trip a real breaker. Fix: stop loop on "no healthy upstream", treat gateway timeout after accepted control as timeout case, fix docs, declare effect. (Same root as D0-9.)
- D467-2 High CONFIRMED Forgejo runs: 7.2 PASS partial on P0 while all 11 cloud_metadata and 16 private_ip URLs accepted (201); the 15 ENFORCED are 422 "Invalid url" for schemes/malformed (URL syntax, not SSRF defence). Note itself says "never a pass". Fix: INCONCLUSIVE when any metadata/private URL accepted.
- D467-3 High PLAUSIBLE (Kong source: request-size-limiting PRIORITY 951 < key-auth 1250): 4.4 unauthenticated probe; gateway auth 401 read as "gateway forwarded body" -> false FIRM NO_SIZE_LIMIT (test_4_4:8-11,168-196,226-249). Labs' 401 is Forgejo's, so today's FAILs right.
- D467-4 High CONFIRMED: 7.4 without signing_secret: _rejects_all returns False, any non-2xx non-5xx -> ENFORCED/SIGNATURE_REQUIRED -> PASS on 404 typo or gateway 401 (test_7_4:203,220-221,257-258).
- D467-5 High CONFIRMED (= PIPE-3): 7.4 signing_secret not SECRET_VALUE -> literal written in clear to config_used.yaml.
- D467-6 Medium CONFIRMED: 4.1 only 429 counts; APISIX limit-count/limit-req/limit-conn default rejected_code 503 -> NOT_VERIFIABLE UPSTREAM_UNAVAILABLE.
- D467-7 Medium CONFIRMED: 4.1 single 5xx at request >=3 ends burst (sent >= _SPOIL_SAMPLE counts requests not failures), contrary to comment.
- D467-8 Medium CONFIRMED (PDF): 4.2 thresholds (connect <=5 s etc.) attributed to NIST SP 800-204A s4.3; s4.3 is external services (SM-DR9), resilience s4.6; no numeric timeout anywhere. Also configuration.md:394-395, page, guarantees.
- D467-9 Medium CONFIRMED: 6.1 sampling skips transport failures with continue (test_6_1:176-179,221-223) -> all failed -> two ENFORCED/CLEAN; error bodies count clean.
- D467-10 Medium CONFIRMED: 6.1 claims internal X-* headers, SQL errors, type-mismatch probe; code checks only x-powered-by/x-aspnet*/versioned server, SQL only java.sql., only malformed-JSON probe; Kong Via 1.1 kong/3.x and X-Kong-* pass.
- D467-11 Medium PLAUSIBLE: 6.1 stack-trace substrings "app/", "at /", path regex match URLs -> FIRM false positives.
- D467-12 Medium CONFIRMED: 6.4 flags {vault://...}, $secret://, $ENV:// references as plaintext CONFIG_SECRET (test_6_4:330-346), contradicting its own remedy.
- D467-13 Medium CONFIRMED agnosticism: lab paths in Field(examples=...) of 7.1 (/identity/api/auth/forgot-password with role user_a; not even crAPI's forget-password), 7.2 (Forgejo hooks, type gitea), 7.3 (/workshop/api/shop/apply_coupon, coupon TRAC075, resource cart that no lab defines); rendered into config.example.yaml:327,341-343,360 and configuration.md:435. Defaults are None so no runtime effect.
- D467-14 Medium PLAUSIBLE thread-safety: 7.3 no Barrier, no connection warm-up; pool.map starts workers serially with TCP+TLS handshakes -> narrow TOCTOU missed -> CONCURRENCY_SERIALIZED PASS. Result collection sound.
- D467-15 Low: 7.3 page says 2xx duplicates indistinguishable/safe; code records VIOLATION FIRM; title wording differs.
- D467-16 Low: 6.2 CORS "*" with credentials described as read primitive (browsers refuse); reflected origin without credentials ENFORCED/CORS_BOUNDED.
- D467-17 Low PLAUSIBLE: 7.2 any 4xx/3xx after control (401 expiry, 422 quota) -> ENFORCED/SSRF_BLOCKED_UNKNOWN.
- D467-18 Low: 7.2 docstring:19-20 "transport refusal of bad scheme -> ENFORCED", code NOT_VERIFIABLE.
- D467-19 Low: NIST SP 800-204 s3.2.2 still cited for SSRF in guarantees.md 7.2 and ssrf_payloads.py, though dropped 2026-10-28 (it is "Internet-based Attacks").
- D467-20 Low: 4.1 page says hourly/daily limit not reached by short burst (count decides, not window).
- D467-21 Low: 4.3 VIOLATION claims no health check but cites only breaker artifact; guarantees lists Kong response-ratelimiting as breaker.
- D467-22 Low hard-rule: test_4_2:372-376 f"{100} concurrent requests" magic number and overclaim.
- D467-23 Low PLAUSIBLE: 7.1 "served then refused" (throttle) -> FLOW_NOT_ACCEPTED not control.
- D467-24 Low CONFIRMED (= CORE-12): 7.3_002 logged twice.
- D467-25 Low: 6.2 cites ASVS 3.4.3 (CSP) but only substring frame-ancestors; frame-ancestors * passes.
- D467-26 Info: 4.1/4.4 gateway-derived limit branches unreachable (documented); if enabled would pick APISIX time_window 60 over count.

Checked and sound: 4.1 burst/spoofing mapping, Forgejo FIRM wording; no false FAIL on crAPI 503s; 4.2 Kong/APISIX semantics; 4.3 defaults handling, NOT_ACCESSIBLE vs NOT_SUPPORTED; 4.4 Forgejo FAILs (Forgejo's 401); 6.1 proofs, ERROR_NOT_PROVOKED; 6.2 crAPI FAIL (6.2_001), X-XSS-Protection not required; 6.4 spoiling and masking; 7.1 crAPI FAIL CERTAIN (7.1_012); 7.2 no VIOLATION without OOB proof, benign control; 7.3 results via pool.map on main thread, client counter/collector locked, only 2xx success; 7.4 positive control signs raw bytes; NIST 800-204 s4.5.3/4.5.1 cited correctly.
