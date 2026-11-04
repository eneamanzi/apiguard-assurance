# Findings PIPE (saved by main from the agent's text reply; condensed)

Counts: 1 High, 3 Medium, 9 Low, 1 Info. One lab run (forgejo-kong copy, no gateway, test_ids 4.3/5.1, preflight + spec only, nothing created).

- PIPE-1 High regression CONFIRMED: 23/25 native tests catch only SecurityClientError (some AuthenticationSetupError); only 7.2, 7.3 have top-level except Exception; engine _execute_single_test (engine.py:1626-1636) has no guard; run() except Exception -> exit 10, Phase 7 never runs, no report, all verdicts lost. BaseTest docstring (tests/base.py:82-83,105-106) and overview.md:256, assessment-model:130 say unexpected exception -> ERROR. v0.1.0 had per-test except Exception; dropped in block 6 (groups D-J). Fix: guard in _execute_single_test -> test._error(exc).
- PIPE-2 Medium PLAUSIBLE: renderer.py:276-279 _safe_json_dumps only replaces "</"; "<!--" + "<script" in a target body (previews cut at 1000 chars can drop "-->") puts the script data block in double-escaped state -> HTML report broken (not XSS). Fix: escape < > & as < etc.
- PIPE-3 Medium CONFIRMED code: config_used.yaml header promises no secret; 7.4 webhook_endpoint.signing_secret not marked SECRET_VALUE -> literal written in clear (labs unaffected, they use ${VAR}).
- PIPE-4 Medium CONFIRMED lab: all-SKIP run exits 0 CLEAN (executed_tests 0); exit-codes.md:26 says "A run never ends 0 without running at least one test".
- PIPE-5 Low: fail_fast also on P0 INCONCLUSIVE (engine.py:1658-1688, configuration.md:297); exit-codes.md and assessment-model:174 say FAIL or ERROR.
- PIPE-6 Low: dag.py:408-410 depends_on met by INCONCLUSIVE too; assessment-model:97 says PASS or FAIL; :106 says every test calls acquire_tokens() but engine obtains declared credentials (engine.py:1603-1610).
- PIPE-7 Low CONFIRMED run: generate-seed exits 2 (no SPEC, no --config) and 10 (bad -c), docs list 0/1; exit-codes says 2 only from framework; validate-config also 10 for unreadable spec/test defs; list-tests missing in "Other commands".
- PIPE-8 Low: validate-config downloads specification.url (cli.py:507-510), which goes through the gateway on Forgejo labs; 02-cli.md:17,114-115 says it never sends a request to the API.
- PIPE-9 Low: config_used.yaml written before Phase 2 (engine.py:903); previous run's report files not removed; console Reports list uses is_file() -> may show stale files; signals deferred only in Phase 6; exit-codes.md says no report files written.
- PIPE-10 Low CONFIRMED lab: report header shows min_priority/strategies even when test_ids overrides (builder.py:491-509); test_ids not in report.
- PIPE-11 Low: openapi.py:17-18,232-234,402-405 docstrings say relative $ref of downloaded spec resolve; same module (146-148, ~531) says not supported.
- PIPE-12 Info: openapi.py:419-423 $ref cycles cut to {} silently, recursion_limit 10 unnamed literal; remote $ref fetched by prance without specification.tls; no size cap on spec.
- PIPE-13 Low: engine.py:66-67 "no other module imports engine" (cli does); engine.py:952-953 "Forgejo tokens, repos, gateway routes" (no test creates routes; lab name); engine.py:57 "DELETE each resource" (method configurable).
- PIPE-14 Low agnosticism: comments in derivation.py; cli.py:733 --help example names test-environments/forgejo-kong/config.yaml. No logic branches on lab/gateway in engine/discovery/report/registry.

Checked and sound: selection (test_ids, unknown id exit 10, empty selection exit 10, not_run reasons); DAG (cycles, unknown prereq); needs SKIP pre-run; gateway withheld; fail_fast P0 + not_run + teardown/report; teardown errors never propagate, signal deferral; exit code = generated table; report counters match rows on 3 outputs; all documented report/evidence fields present; autoescape + _escHtml; ${VAR} missing -> ConfigurationError; no secrets in config_used.yaml or evidence on 3 runs; every ToolConfig field used; CLI commands/options vs v0.1.0 all present.

MAIN VERIFICATION of PIPE-1: confirmed with a corrected count. 13 tests have the top-level guard (0.1, 1.5, 3.3, 4.1-4.4, 5.1, 6.4, 7.1-7.4); 16 lack it (0.2, 0.3, 0.4, 1.1, 1.2, 1.3, 1.4, 1.6, 1.7, 2.1, 2.2, 2.4, 2.5, 6.1, 6.2) and the engine has no guard around test.execute (engine.py:1627-1634, only try/finally). v0.1.0 test_1_1 had `except Exception` (2 places).
