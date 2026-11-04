# Findings D1 (saved by main from the agent's text reply; condensed)

Counts: 1 Critical, 4 High, 11 Medium, 11 Low. Lab: curl -i http://localhost:8443/api/v1/orgs and one run of 1.5 only (forgejo-kong copy without http_url); 2 GETs, nothing changed.

- D1-1 Critical CONFIRMED code (labs not hit): 1.2 degraded JWTs stored unredacted when placement is not Authorization (apiKey header or query): tampered keeps original header+signature, alg-none keeps payload -> evidence rebuilds valid user_a token (jwt_tokens.py:108,130,147; test_1_2:285-293; redaction.py:158-185; client.py:799,913).
- D1-2 High CONFIRMED (NIST text checked): 1.7 cites SP 800-63B-4 3.2.2 for per-caller limit; NIST limit is per account; test probes a non-existent account -> FAIL ATTEMPTS_NOT_LIMITED citing NIST on a compliant verifier.
- D1-3 High CONFIRMED: 1.7 repeated_attempts stops only on 429, 5xx/no response, or slowdown (test_1_7:376-413); 403 block, 423, 401 "too many attempts" ignored -> false FIRM ATTEMPTS_NOT_LIMITED.
- D1-4 High CONFIRMED (ASVS 5.0.0 4.1.2 text checked): 1.5 counts HTTP->HTTPS redirect as ENFORCED and recommends it; ASVS 4.1.2 forbids transparent redirects for non-browser endpoints. All 3 labs PASS on a 301.
- D1-5 High CONFIRMED code: 1.1 malformed query-parameter credentials sent as headers (test_1_1:582-591, 400-401) -> ENFORCED without testing anything.
- D1-6 Medium CONFIRMED lab: 1.5 without http_url on non-443 port probes TLS port over HTTP; Kong 400 "plain HTTP request sent to HTTPS port" -> CERTAIN FAIL HTTP_PROCESSED_CLEARTEXT (test_1_5:275-278,356-360). Labs work around via http_url.
- D1-7 Medium CONFIRMED: 1.5 transport failure incl. timeout -> ENFORCED/HTTP_PORT_UNREACHABLE (test_1_5:309-317), against rule 4.
- D1-8 Medium PLAUSIBLE: 1.2 tampered variant changes `sub` -> non-verifying server fails user lookup -> ENFORCED. Tamper a non-identity claim.
- D1-9 Medium CONFIRMED: anchor.py:80-83 accepts anchor when no-credential probe is 429/5xx/transport/redirect (only SERVED rejected) -> 1.2/1.4 CERTAIN on a public endpoint.
- D1-10 Medium CONFIRMED crAPI: 1.2 and 1.4 findings cite no positive/negative control (supporting_refs []); 1.2 variants indistinguishable in evidence.
- D1-11 Medium CONFIRMED crAPI: 1.1 malformed-credential evidence fully redacted (1.1_036-040, 049-053); redaction.py:53-57 comment says kept in clear; declare_public_value never called.
- D1-12 Medium CONFIRMED crAPI: 1.3 finding "valid for 7 days" with no exp/iat in finding or evidence (login token redacted).
- D1-13 Medium CONFIRMED: 1.2/1.3 strip hard-coded prefixes (Bearer/token/Token) instead of CredentialPlacement.prefix; duplicated function (test_1_2:322-347,369-377; test_1_3:218-238); "JWT eyJ..." -> false NOT_A_JWT.
- D1-14 Medium CONFIRMED code: 1.6 empty-value cookie clear never recognised because Set-Cookie already redacted (sid=[REDACTED]) -> false CERTAIN.
- D1-15 Medium PLAUSIBLE: 1.6 calls every cookie a session cookie, requires HttpOnly on XSRF-TOKEN (ASVS 3.3.4 does not).
- D1-16 Medium CONFIRMED (in run outputs): user-visible lab names: test_1_2:154-156 and test_1_3:139-141 "Forgejo's API token is an opaque sha1 value"; test_1_4:122-125 "crAPI issues a stateless JWT"; test_1_6:148-150 "Both lab applications..."; test_1_5:128-130 param description names lab ports (into config.example.yaml/reference).
- D1-17 Low: 1.7 three-reading comparison ignores 429 -> ANSWER_NOT_STABLE.
- D1-18 Low CONFIRMED: 1.7 ATTEMPTS_NOT_LIMITED evidence_ref is attempt 1 (1.7_007), not 101.
- D1-19 Low: 1.7 claims password masked in comparison; only name masked.
- D1-20 Low: 1.7 docstring says 1 failed attempt on real account, code sends 3 (lockout risk).
- D1-21 Low: 1.7 ENFORCED/TIMING_TOO_SMALL for reading the code says "says nothing" (rule 1).
- D1-22 Low: 1.3 "unless a key is supplied" (no way to supply); non-numeric exp -> "no exp"; exp<=iat -> NO_IAT_CLAIM; _human rounds 47h to "1 day".
- D1-23 Low: 1.2 NEEDS_KEY_MATERIAL although crAPI publishes jwks; real reason not implemented.
- D1-24 Low: 1.5 HSTS request no SecurityClientError handling (:396) -> whole test ERROR; regex misses quoted max-age; title "Credential-bearing" but no credential sent.
- D1-25 Low: 1.1 redirect NOT_VERIFIABLE in no_credential but ENFORCED in path_variants; cleanup note wording.
- D1-26 Low PLAUSIBLE: 1.4 "keeps access for rest of lifetime" CERTAIN from immediate reuse (gateway cache).
- D1-27 Low CONFIRMED: guarantees.md 1.5/1.6 cite ASVS 4.0 numbers labelled 5.0.0; 1.5 says "with a valid token".

Checked and sound: no secrets/JWT/tokens in outputs; auth helpers redact, secrets registered first, 1.4 temp credential registered; 1.4 valid-before-revocation proof sound; 1.2 crAPI ALG_NONE FAIL real; 1.1 crAPI FIRM findings proven, Forgejo TENTATIVE justified, 503/429/5xx never ENFORCED; 1.3 computation; 1.5 with http_url correct apart from D1-4; 1.6 SKIP and parsing; 1.7 enumeration bodies and timing statistics sound (medians 96/7, 401/3, 397/4 ms), slowdown rule; auth_placement, jwt_tokens decode/constructions.
