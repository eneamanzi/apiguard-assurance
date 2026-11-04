# Findings EXT (saved by main from the agent's text reply; condensed)

Counts: 2 Critical, 2 High, 6 Medium, 9 Low, 1 Info. Lab: 4 curl GETs on Forgejo+Kong; displayed Schemathesis command limited to --method GET (723 GETs); displayed testssl on localhost:8443 and localhost:8000. Nothing created.

- EXT-1 Critical CONFIRMED (Schemathesis 3.39.16 source, offline repro, live run): connector passes --base-url without path (schemathesis.py:100-105; ext_test_3_1:114-120); Schemathesis 3.x uses urlsplit(base_url).path as base path, discarding Swagger basePath /api/v1 -> 723 requests none under /api/v1, all 404; Schemathesis warned "only 4xx ... Check base URL" yet "241 passed" -> Forgejo labs PASS complete "found no unvalidated input". Page validation false. Fix: base_url + spec base path (discovery has it); only-4xx -> NOT_VERIFIABLE.
- EXT-2 Critical CONFIRMED (outputs/crapi/tools/ext_3_1_schemathesis_output.json): crAPI 27 failing ops = 24 Kong 503 "failure to get a peer from the ring-balancer", 2 x 500, 1 schema; 17/20 findings are 503s as FIRM INPUT_NOT_VALIDATED; native tests classify this as NOT_VERIFIABLE/UPSTREAM_UNAVAILABLE; page says "real 500s"; compatibility.md:80 blames variance on Schemathesis.
- EXT-3 High CONFIRMED source: no --data-generation-method -> positive only; negative_data_rejection never runs; code/model/page claim "valid and invalid" (schemathesis.py:4-15,100-116; ext_test_3_1:10-19; external_tools.py:233-237); its allowed statuses include 401/403/404/5xx anyway.
- EXT-4 High CONFIRMED: _parse_junit (schemathesis.py:180-212) reads only <failure>; <error>/<skipped> ignored -> ENFORCED when nothing ran; exit 1 for errors accepted; contradicts rule 11.
- EXT-5 Medium: 500 on valid input / response schema drift reported as "does not validate its input".
- EXT-6 Medium CONFIRMED (3 reports): testssl WARN engine_problem (scan problem) shown as TLS note about target, leaks /home/manzi/... path (ext_test_1_5:74,219-220,281-291).
- EXT-7 Medium CONFIRMED (testssl manual): exit 1 = one error, not "findings detected" (testssl.py:83-88,295-308; base.py:114-121); >=2 errors -> ERROR dropping HIGH findings; FATAL scanProblem (ip_fatal) ignored -> ENFORCED with an IP unscanned (plausible).
- EXT-8 Medium CONFIRMED prompt/exit 245: testssl Popen inherits stdin (base.py:486-497), no --warnings batch; on plain HTTP it prompts "Really proceed?" -> hang until timeout from a terminal -> ERROR. Fix: stdin DEVNULL + --warnings batch.
- EXT-9 Medium PLAUSIBLE: ffuf -maxtime cut on last job unnoticed (ffuf.py:80-82,203-251) -> ENFORCED on partial search.
- EXT-10 Medium CONFIRMED: every testssl HIGH/CRITICAL finding text says "downgraded or traffic decrypted" incl. chain of trust/expired cert (ext_test_1_5:243-249).
- EXT-11 Low CONFIRMED: base.py:516 'schemathesis'.rstrip('.sh') -> 'schemathesi' in message.
- EXT-12 Low: tools' stderr discarded; raw_stderr never set (base.py:566; testssl.py:298).
- EXT-13 Low: schemathesis displayed command has absolute venv binary /home/manzi/.local/..., absolute spec path, trailing space; ffuf same wordlist placeholder for all jobs (words unsaved), -maxtime omitted.
- EXT-14 Low: crAPI 27 failing ops but 20 violations recorded; text truncated mid-curl.
- EXT-15 Low PLAUSIBLE: schemathesis found only on PATH though docs call it a library (pipx/unactivated venv -> SKIP).
- EXT-16 Low: testssl security_headers (MEDIUM, "--") shown as TLS note; 6.2's question (rule 10).
- EXT-17 Low hard-rule: schemathesis request timeout 5000 ms hard-coded (schemathesis.py:55-56); new config key = owner decision.
- EXT-18 Low PLAUSIBLE: base_url with path -> doubled prefix in ffuf re-verification/calibration.
- EXT-19 Low doc-drift: ffuf page "35 sensitive paths" (code 38); guide _evaluate(result, artifact_ref) vs (result, run: ToolRun); "exactly four keys" (ffuf adds base_urls); connector export step; ext_test_<tool>_ naming and nuclei example in registry.py:13,19, _template_ext_test.py:7; evidence-format.md:46 EXT.0.1.NUCLEI; base.py "env var" discovery; extra_flags not declared by ffuf/schemathesis.
- EXT-20 Info: nuclei dormant, docs consistent; install_tools.sh still downloads it (documented).

Checked and sound: no shell=True; temp files cleaned, child killed on timeout; no temp paths in commands on 3 labs; _relativize_display_path sole normaliser; missing tool SKIP, disabled -> not_run, missing SecLists ERROR (documented); ffuf design and re-verification sound; ffuf Forgejo FAILs (/api/healthz, /api/swagger 200 vs sibling 404) proven; testssl revocation exception precise; testssl command reproducible; schemathesis command valid for 3.39; artifact pinned before _evaluate; no lab logic in connectors/external_tests.
