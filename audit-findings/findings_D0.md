# Findings D0 (saved by main from the agent's text reply; condensed)

Counts: 3 High, 8 Medium, 5 Low, 2 Info. Lab: read-only (docker ps/inspect; GET http://172.22.0.3:3000/api/v1/orgs -> 200; GET http://172.23.0.8:8000/workshop/api/mechanic/ x2 -> 401). Nothing created.

- D0-1 High CONFIRMED: 0.1 undeclared_methods on parametric paths: probe is random_sibling_path(template) and calibration is sibling_pattern(template) = same kind of random path -> always SAME_AS_UNKNOWN -> ENFORCED/METHOD_NOT_SERVED without evidence; UNDECLARED_METHOD_KNOWN impossible there (test_0_1:237-255,299-320; references.py:507-532,610-641). 95 of 139 METHOD_NOT_SERVED on Forgejo labs, e.g. 0.1_073 POST /api/v1/admin/quota/groups/<rand> 404. Undeclared PUT /items/{id} answering 404 item-not-found -> PASS. Page claims FIRM reporting.
- D0-2 High CONFIRMED crAPI: 0.1 _probe_version (test_0_1:525-535) lacks REFUSED_BEFORE_ROUTING guard; identity catch-all 401 (0.1_161, 0.1_162; calib ref_070-073 reliable at 401) recorded ENFORCED VERSION_ABSENT -> PASS complete on unobserved v1/v3.
- D0-3 High CONFIRMED (runs + lab GETs): 0.4 PASS on both Kong labs rests only on derived localhost candidates refusing; declared backends ADDRESS_NOT_RESOLVABLE (Kong reports hostname, cf. CORE-8); they answer directly from the run host (Forgejo container 200; crAPI workshop 401 identical to via-Kong). Page promise "declared addresses did not answer" and Limitation 3 false. Fix: no PASS while every declared address is unverifiable; Kong adapter keep resolved IP.
- D0-4 Medium CONFIRMED: 0.1 page (63-67, 74) describes an APIGUARDPROBE method reference + log key test_0_1_method_reference never in src (introduced in docs only, 0ce8993).
- D0-5 Medium PLAUSIBLE: static-path probe calibrated on sibling that a parametric route captures (/users/search vs /users/{id}) -> false VIOLATION/UNDECLARED_METHOD_KNOWN FIRM.
- D0-6 Medium CONFIRMED code: test_0_1:307-346 SERVED+SAME_AS_UNKNOWN falls to VIOLATION/UNDECLARED_METHOD_HANDLED CERTAIN with false text "random siblings answered otherwise"; SPA catch-all 200 -> CERTAIN findings on every path.
- D0-7 Medium CONFIRMED code: 0.1 cleanup (test_0_1:366-384): 2xx POST without Location neither deleted nor named; 2xx PUT on non-parametric real path followed by unauthenticated DELETE on the real resource (rule 5/7).
- D0-8 Medium PLAUSIBLE: 0.2 backend-refusal guard (test_0_2:253-291) may sample gateway auth plugin 401 rather than backend; only first reliable of 3 shortest paths.
- D0-9 Medium CONFIRMED crAPI: 0.1 lost the page-documented crAPI FAIL (PUT /workshop/api/shop/orders): all 54 workshop probes 503 ring-balancer after 7.2 (CHANGES_DATA, 14:33-14:34) made Kong passive health mark upstream unhealthy; 0.1 (STRESSES_TARGET) ran right after. Honest NOT_VERIFIABLE but validation lost. Fix: effect ordering / wait for upstream health; re-validate.
- D0-10 Medium = PIPE-1 for 0.2, 0.3, 0.4.
- D0-11 Medium CONFIRMED: guarantees.md:170-171 promises configured backend list for 0.4; test has no params, needs GATEWAY.
- D0-12 Low PLAUSIBLE: 0.3 (test_0_3:284-349) any DIFFERENT answer (308 to v2, 400, 405) without Sunset -> "still served" VIOLATION.
- D0-13 Low PLAUSIBLE: 0.1 route drift (test_0_1:639-644) regex route ^/users/\d+$ vs template {id} -> false CERTAIN ROUTE_NOT_DOCUMENTED.
- D0-14 Low CONFIRMED: 0.2 findings omit guard calibration refs (ref_003/004) from supporting_refs.
- D0-15 Low CONFIRMED: 0.2 page calls crAPI workshop 404 "Spring's HTML 404"; evidence shows gunicorn/Django.
- D0-16 Low: derivation.py:29-30 says service_prefixes used by 0.1 (used by ext.0.1.ffuf and sampling); :194-197 _PRIVILEGED_SEGMENTS comment self-contradictory.
- D0-17 Info = PIPE-5 fail-fast INCONCLUSIVE.
- D0-18 Info: references.py:709-756 gateway_refusal has no spoiling rule (only caller 0.2 filters); undocumented for future callers.

Checked and sound: 0.2 Forgejo FAIL /api-<rand> and crAPI FAILs (gunicorn, Go 404) proven; 0.2 APISIX PASS; hmac-route neighbours excluded; 0.3 Forgejo/APISIX FAIL proven (0.3_002, ref_005/006, no Deprecation/Sunset); 0.3 crAPI SKIP correct; 0.4 APISIX FAIL CERTAIN justified; 0.1 route drift FAIL true on 3 labs; METHOD_REJECTED 405/501; REFUSED_BEFORE_ROUTING sound; 0.3 credential retry; 0.4 name resolution; categorize per IANA/RFC 9110 s15; calibration spoiling, normalisation; version_siblings facts; standards consistent; domain_0 agnostic (comments only).
