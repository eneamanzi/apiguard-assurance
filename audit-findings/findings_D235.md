# Findings D235 (saved by main from the agent's text reply; condensed)

Counts: 0 Critical, 8 High, 9 Medium, 8 Low. No lab requests sent, nothing changed.

- D235-1 High CONFIRMED oracle: 5.1 FAIL CERTAIN "requests are not logged at the gateway" (test_5_1:187-204) but Kong labs set KONG_PROXY_ACCESS_LOG=/dev/stdout and APISIX writes nginx access log by default; Admin API cannot see native access log. Fix: oracle = "no log-shipping plugin to separate system (ASVS 16.4.3)", not CERTAIN, limitation.
- D235-2 High CONFIRMED agnosticism: 5.1 matches Kong/APISIX plugin name fragments (test_5_1:53-66) over config_values concept, user-visible text names Kong/APISIX; contrary to D7 and to 3.3. Fix: request_logging concept in adapters.
- D235-3 Medium CONFIRMED: 5.1 markers matched on any item location incl. service/route names (kong.py:310-320, apisix.py:325-372); `datadog` is metrics; route-scoped plugin counted as all requests. Service "datadog-proxy" -> false PASS.
- D235-4 High CONFIRMED (crAPI run 2.5_004): 2.5 mass_assignment ENFORCED when read-back contains none of injected fields (test_2_5:293-315, 389-402); Forgejo PASS rests on `owner` only. Fix: NOT_VERIFIABLE if no injected field present.
- D235-5 High CONFIRMED: helpers/resources.py:282 drops extra_body silently when create body not a dict -> 2.5 ENFORCED with nothing injected.
- D235-6 High CONFIRMED (crAPI 2.5_002): SENSITIVE_FIELD substring key match, value ignored; crAPI finding is masked card_number XXXXXXXXXXXX0796 returned to its owner; page calls it real weakness. ssn~classname, token~token_type.
- D235-7 High CONFIRMED: 2.2 modify/delete have no positive control (only cross_user_read); _judge_cross catch-all (test_2_2:327) maps 400/422/405/redirect/OTHER to ENFORCED; modify body `{}` -> 422 from validation counted as refusal. P0.
- D235-8 High PLAUSIBLE: 2.2 and 2.1 count 401 for user_b/user_a as enforcement without checking credential works (auth_static.py:97 stores token unchecked); expired user_b_token -> PASS complete with BOLA.
- D235-9 Medium CONFIRMED: 2.2 BOLA_MODIFY/BOLA_DELETE CERTAIN without proof of effect; "confirmed by user_a read" false (re-read unjudged, compares nothing; no read after DELETE).
- D235-10 Medium CONFIRMED (crAPI): 2.1 BFLA finding says "confirmed by admin positive control" but supporting_refs [] (control is ref_005); _judge called without reference_responses (test_2_1:285-303).
- D235-11 Medium: 2.1 CERTAIN because admin served does not prove privileged op; privilege only from admin/management path heuristic. Keep FIRM.
- D235-12 Medium CONFIRMED (crAPI): 2.4 no calibration on sibling; crAPI random paths give same 401 fingerprint (ref_010/011) as the 8 SIBLING_REFUSED -> PASS complete unproven; catch-all 2xx would give CERTAIN VERSION_DROPS_AUTH (never exercised).
- D235-13 Medium CONFIRMED: 2.4 maps NO_RESPONSE/5xx/429/404 on documented path to NOT_APPLICABLE "not protected" (test_2_4:269-279), violates rule 4.
- D235-14 Medium CONFIRMED: 3.3 treats replay window None ("not stated or replay_unlimited", concepts.py:268-280) as REPLAY_UNBOUNDED CERTAIN; APISIX leaves None when schema unreadable; inconsistent with algorithm sub-test.
- D235-15 Medium PLAUSIBLE: 3.3 cites RFC 6151/6194, SP 800-107 for "HMAC-SHA1/MD5 broken, attacker can forge"; RFC 6151 s2.3 and RFC 6194 say HMAC not practically affected; 300 s window is methodology, not SP 800-107.
- D235-16 Medium CONFIRMED (crAPI): orders 6,7,8 created by 2.2/2.5 left on target, credit spent (70.0); only log.info, no InfoNote; 2.5 page says "deletes both" (rule 7).
- D235-17 Medium CONFIRMED: 2.1 docstring/page promise config ("configuration adds or corrects", "configured confirmed operation") that does not exist; page says it subsumes 2.3 but no destructive request sent.
- D235-18 Low: 2.1 method_not_confused NOT_APPLICABLE on all labs (HEAD rarely documented), unvalidated (rule 9); public GET vs refused HEAD -> CERTAIN METHOD_CONFUSION.
- D235-19 Low: 2.4 declares whole version absent from one 404 (test_2_4:149-165).
- D235-20 Low doc-drift: 2.2 page says Forgejo 403, run 404 (2.2_003); "only one object tested" vs owned_object_resources; 2.4 crAPI basis description wrong; 2.5 "keeps none" / docstring patterns *key, credit* not in list.
- D235-21 Low PLAUSIBLE: 2.4 should cite API9:2023; catalogue vs test ids differ (2.1 V8.2.2 vs 8.2.1; 2.2 800-162 s2.2 vs s2.3; 2.5 SC-4 vs AC).
- D235-22 Low: test_3_3:61-66 comment parks ASVS 4.1.5 "group-F draft" while page says verified 2026-10-27; not in TestInfo.
- D235-23 Low hard-rule: test_2_5:384,400 `node[:5]` magic number, unstated limit.
- D235-24 Low: test_2_5:331-341 _read_object drops exc.record on transport error -> OBJECT_NOT_READABLE (rule 4).
- D235-25 Low agnosticism: lab names in comments test_2_1:168, 2_2:340, 2_5:353, 2_4:10-11,175-183,231.

Checked and sound: crAPI BOLA_READ proven (2.2_002/003); crAPI BFLA proven (2.1_001, ref_005) except citation; 2.1 404 only enforced when admin served; 2.2 Forgejo PASS with owner control and cleanup; 2.5 Forgejo sensitive-field and cleanup; owned_object path resolution; resources teardown and secrets; 3.3 all-policies, SKIP when unreadable, PASS matches artifacts; 5.1 disabled plugins and empty read; no print/pass/TODO/bare except; no credential leak in this area.
