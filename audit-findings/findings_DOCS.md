# Findings DOCS (saved by main from the agent's text reply; condensed)

Counts: 10 Medium, 17 Low. Ran: link/anchor checker (all resolve), read-only lab readiness curls, validate-config (scratch + forgejo-kong), one run test_ids [6.2] no ext tools (scratchpad/run62/).

- DOCS-1 Medium: fail-fast "FAIL or ERROR" in exit-codes.md:58, assessment-model.md:174, select-tests.md:124-125, design-properties.md:524, methodology.md:118, config.example.yaml; engine also INCONCLUSIVE; configuration.md:297 correct.
- DOCS-2 Medium: security-model.md "burst of up to 300 requests (default)"; max_burst default 150.
- DOCS-3 Medium: configure-a-target.md s3 and config.example.yaml CREDENTIALS header: wrong roles (2.2 "planned", user_b can be left out -> P0 2.2 SKIP; admin for 1.4; user_a list wrong).
- DOCS-4 Medium CONFIRMED run: configure-a-target s1 "18 of the 29" (real "18 of the 28", names 1.4, 2.2, 2.5); README "29 native tests" (28; 31 total).
- DOCS-5 Medium CONFIRMED: "${VAR} in a YAML comment stops the tool" false (configure-a-target Rules, first-assessment Troubleshooting).
- DOCS-6 Medium: first-assessment s6 expects 8 SKIPs incl. nonexistent 5.2; run has 7 (1.2, 1.3, 1.6, 2.4, 7.1, 7.3, 7.4).
- DOCS-7 Medium (= CORE-10): overview.md "Not thread-safe; execution is sequential" vs lock for 7.3.
- DOCS-8 Medium: "Only WHITE_BOX reads gateway or acts as admin" false: BLACK_BOX 0.1, 0.2, 4.1, 4.4, 6.4 read gateway via optional_needs; GREY_BOX 2.1 uses admin optionally; strategies:[BLACK_BOX] does not keep the Admin API untouched (also CLAUDE.md, native-test guide).
- DOCS-9 Medium: report-schema.md example stale (references as strings, 18 tests, old title); SKIP row "tool disabled" (actually not_run); compatibility.md contract status list lacks INCONCLUSIVE.
- DOCS-10 Medium CONFIRMED run: cli.md list-tests --json table lacks effect, optional_needs, references, sub_tests.
- DOCS-11 Low: external tests listed under Not Run, not "disappear" (select-tests, ext guide).
- DOCS-12 Low: stale figures: 1.1 with path_seed 261 not-verifiable (not 63); partial passes 5 of 15 (not 6); coverage lowercase in JSON (jq with PARTIAL matches nothing); reset crAPI 13 FAIL (not 15).
- DOCS-13 Low: adapter guide: 4.3 target_health / 3.3 routes wrong (0.4, 0.1/0.2); message "Gateway adapter not configured" not in src; verify step lists 6.4, omits 0.4, 5.1.
- DOCS-14 Low: ext guide TestInfo snippet lacks effect, sub_tests -> TestDefinitionError; _evaluate signature.
- DOCS-15 Low: "1.5 uses httpx directly" stale; 2.5, 6.1, 6.2, helpers/resources.py import httpx for type hints.
- DOCS-16 Low: acquire_tokens contradictions (0.3, 7.3 still call it); native guide add_fail_evidence(); category_of location.
- DOCS-17 Low: packaging contents misstated (sdist has CHANGELOG.md, config.example.yaml; no .gitignore).
- DOCS-18 Low: compatibility.md crAPI "3 of 31" vs "2 of 32"; run has 4 INCONCLUSIVE.
- DOCS-19 Low: integration guide s3 "1.4 token fixed name" obsolete.
- DOCS-20 Low (= PIPE-7, PIPE-9): other commands' exit codes; exit 10 writes config_used.yaml.
- DOCS-21 Low: config.example.yaml mentions injection_resource (gone); gateway comment lists wrong tests; resources "Used by" omits 2.2, 2.5, 7.3.
- DOCS-22 Low CONFIRMED run: seed_generator.py:178 template header uses obsolete INCONCLUSIVE_PARAMETRIC/BYPASS vocabulary.
- DOCS-23 Low PLAUSIBLE hard-rule: --log-level debug lets httpx log full URL incl. query credential (send_as.in: query).
- DOCS-24 Low: evidence-format "passwords never appear" vs MIN_SECRET_LENGTH 8.
- DOCS-25 Low: index.md 48 generated files (47); no "what is still open" doc in docs/project/.
- DOCS-26 Low agnosticism: compatibility.md "No test or helper contains Forgejo paths" vs 7.2 example and 1.3 note.
- DOCS-27 Low: D6 lists 2.2, 7.3 as future; compatibility ties 1.0.0 to deleted "plan, block 8"; methodology data exposure P2 vs 2.5 P1.

Checked and sound: links/anchors; ports/containers/images vs compose; readiness curls; validate-config lab output (3 of 31 SKIP: 7.1, 7.3, 7.4); install_tools versions + ffuf checksum; dev:check vs pyproject; check_config_keys 169; exit codes and signals; evidence/preview limits; connections example; 1.1 finding example (78 anonymous GETs); crAPI detection table (13/10/4/4, 37 findings); helper names in guides; ${VAR} rules in configuration.md; guarantees priorities = list-tests; audit-v0.1.0 marked historical; CA/B 200-day, ASVS 13.2.1 citation.
