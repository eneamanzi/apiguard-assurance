# Operational Plan

> **Audience:** project owner, Claude Code · **Status:** active (created 2026-10-06) · Single source for "what do we
> do next". Update the status column as steps are completed.

## Where we are (updated 2026-10-10)

- **Done:** documentation restructured (phase 2, pages 2.1 and 2.4 written); open questions decided (phase 3);
  code blocks 1, 2, 3, 4, 4b, 5, 5b, 5c and 5d (configuration structure, interface contract and versioning, secret
  redaction, console interface, prerequisites between tests); integration guide written. The tool behaves as before
  on the lab: results identical to the baseline.
- **Next step:** block 7 cRAPI lab together with the infrastructure part of block 8 agnosticism (plan it with the
  owner first).
- **Then, in order** (revised 2026-10-09, owner: everything around the tests first, the test review last): block 7
  cRAPI lab together with the infrastructure part of block 8 agnosticism (neutral gateway data, "not applicable"
  result, Forgejo defaults to configuration; the per-test parts go into the test review) → block 9 CI and generated
  docs, 10b, 10 roadmap, 2.3 knowledge translation (with Q-33) → block 6 test review → block 6b E2E on both labs →
  missing methodology sub-tests and new tests (Q-32, Milestone 2). To decide before the test review: where release
  **1.0.0** goes (before it, then splitting 6.4 changes test IDs and would be breaking; or after it).
- **Deferred:** Q-05 licence, Q-06 security policy, Q-11 sslyze licence (product distribution unknown).

## Ground rules

1. **One step at a time, in order.** A step starts only when the previous one is done.
2. **Who does what.** Claude prepares (writes pages, collects evidence, proposes options); the owner tests and
   decides. Claude never closes an open question and never changes code or project files without an explicit go.
3. **Work in the official repository folder.** No throwaway clones, no shifted ports. A fresh state is obtained
   with the reset command in step 0 of [`first-assessment.md`](../getting-started/first-assessment.md).
4. **Every step has a check the owner can run** and a "done when" condition.
5. **Commits are made by the owner**; Claude gives the command at the end of each step.

## Phase 1 - Validate the getting-started guide

| # | Step | Who | Check / done when | Status |
|---|---|---|---|---|
| 1.1 | Simplify `installation.md` and `first-assessment.md` (single path, standard ports, reset in step 0) | Claude | pages readable top to bottom with no detour | done |
| 1.2 | Follow `installation.md` then `first-assessment.md` literally, from the official folder, **without interrupting the run** | owner | exit code `1`, three report files in `outputs/`, three `200` in the readiness check; every unclear point noted | done |
| 1.3 | Fix the pages from the notes of 1.2, mark them verified | Claude | owner confirms | done |
| 1.4 | Commit | owner | `git status` clean | done (`b8cdd9e`) |

## Working order (agreed 2026-10-06)

Phases 2 and 3 are interleaved: a group of open questions is decided before the guide that depends on it, so no
page is written twice.

| Order | Step | Status |
|---|---|---|
| 1 | Phase 1 closed (commit) | done |
| 2 | 3.1 Test lab (Q-46) | done |
| 3 | 2.1 `guides/usage/` (current behaviour, links to open questions where in doubt) | written 2026-10-06, owner review pending |
| 4 | 2.4 Entry points (README first) | written 2026-10-06, owner review pending |
| 5 | 3.A Close the questions already settled (Q-01, Q-42, Q-07, Q-08) | done |
| 6 | 3.B/3.C quick decisions without code: ~~Q-12~~ (closed), ~~Q-03~~ (closed), ~~Q-14~~ (closed), ~~Q-37~~ (decided, moved to 3.D), ~~Q-49~~ (closed), ~~Q-09~~ (closed), ~~Q-32~~ (moved to 3.D with Q-29), Q-33 (with 2.3 translation) (one at a time, discussed in full) | done (Q-33 waits for step 10) |
| 7 | 3.B remaining: ~~Q-02~~ (closed), ~~Q-15~~ (decided, moved to 3.D), ~~Q-17~~ (light fix done, rewrite moved to 3.D) (Q-25 moved to 3.D) | done |
| 8 | 3.C (done 2026-10-07): ~~Q-10~~ (decided, moved to 3.D), ~~Q-24~~ (decided, moved to 3.D), ~~Q-31~~ (decided, moved to 3.D), ~~Q-47~~ (closed); then ~~Q-11~~ (deferred, owner asks), ~~Q-18~~ (moved to 3.D, agnosticism), ~~Q-26~~ (decided, moved to 3.D), ~~Q-30~~ (decided, code items moved to 3.D) | done |
| 9 | 3.D Code work, block by block (see Phase 4 below): each block is planned in detail with the owner, then implemented one change at a time | in progress (blocks 1-5 done) |
| 10 | 2.3 `knowledge/` translation (with Q-33) | to do |

Phase 4 (implementation) follows the block order below; Phase 5 is block 9.

## Phase 2 - Finish the documentation

Each step: Claude writes the section from verified facts, the owner reads it as a user (is it clear, can I follow
it), Claude fixes, owner commits.

| # | Step | Content | Status |
|---|---|---|---|
| 2.1 | `guides/usage/` | configure a target, select tests, read the report | written 2026-10-06, updated with blocks 1-5; owner review pending |
| 2.2 | `guides/integration/` | one page, `integrate-apiguard.md`: install with pip, configuration and credentials, run, exit codes (script fixing the old `set -e` defect), reading the results with `jq`, stopping, effects on the target, versions; no CI-specific example | written 2026-10-09; owner review pending |
| 2.3 | `knowledge/` translation | methodology, tool decisions, design properties in English; background as a summary | to do |
| 2.4 | Entry points | new README (English only, Hatch, Linux), CONTRIBUTING, CHANGELOG, `docs/index.md`, CLAUDE.md as a thin router, clean `maintainer-commands.md`, remove `README.en.md` duplicate | written 2026-10-06; owner review pending |

## Phase 3 - Decide the open questions

`OPEN_QUESTIONS.md` holds every doubt found so far. One session per group: Claude presents each question with
the evidence and 2-3 options, the owner decides, the decision is written in the entry. **No code is changed in
this phase**; decisions feed Phase 4.

Groups re-organised on 2026-10-06 by how much code each question needs (owner decision). Closing a question
means deleting its entry from `OPEN_QUESTIONS.md` and writing the decision in the log below.

| # | Group | Questions | Note |
|---|---|---|---|
| 3.1 | Test lab | - | done 2026-10-06 (Q-40, Q-41, Q-46 closed) |
| 3.A | Already settled | - | done 2026-10-06 (Q-01, Q-07, Q-08, Q-42 closed) |
| 3.B | Decision + documentation only | Q-33 | with the `knowledge/` translation |
| 3.C | "Document as is" or "change the code" | - | a question whose decision needs code moves to 3.D |
| 3.D | Code or process changes | all remaining questions except Q-33 and the deferred ones | organised in blocks, see Phase 4 |
| - | Deferred | Q-05, Q-06, Q-11 | licence, security policy, sslyze AGPL (waiting for the product's distribution model) |

## Phase 4 - Implement the decisions

Block order agreed on 2026-10-07. Every block is first planned in detail with the owner (scope, files, how it is
verified); then each change follows the usual rule: Claude states the files and the plan, waits for the go, changes
them, verifies on the lab with only the affected tests, and gives the owner a check to run. The documentation page
affected is updated in the same change.

| # | Block | Questions | Content | Risk | Status |
|---|---|---|---|---|---|
| 1 | Safety net | Q-39 (+ Q-15) | development helper `scripts/compare_reports.py` (compare two reports, development only, to be removed later); `ruff format` + check in `dev:check` (Markdown excluded); `import-linter` with the dependency rule in `dev:check` (after fixing Q-15); the two rule exceptions written in CLAUDE.md and `coding-rules.md`. Pre-commit hook comes with block 9 | low: adds checks only, no behaviour change | done 2026-10-07 |
| 2 | Cleanup | Q-19, Q-28, Q-26 (descriptions), Q-24 (`sslyze.extra_flags`) | stale paths and comments, comments that contradict the code, one no-op field (Q-15 done in block 1) | very low | done 2026-10-07 |
| 3 | Small bugs | Q-35, Q-21, Q-48, Q-55 (lab setup), Q-36 and Q-27 (remove) | spec fetch hang, `generate-seed` stdout, warning messages, lab setup after deletions, two unwired features removed | low-medium | done 2026-10-07 |
| 4 | Configuration structure | Q-53, Q-37 | one definition per parameter (`src/test_config/`), every test has a config model, automatic wiring (mismatch stops the run) | medium: after block 1 | done 2026-10-08 |
| 4b | Immutable list parameters | Q-57 | safety check: list parameters as tuples | low: same files as block 4 | done 2026-10-08 |
| 5 | Contract 1.0 | Q-25, Q-20, Q-22, Q-23, Q-45, Q-58, Q-50 (rule), Q-54, Q-10, Q-60, Q-31, Q-26 ("not run by choice" list), Q-44 | everything an integrator sees; then the stability policy | medium-high | done 2026-10-09 |
| 5b | Console output | Q-59 | readability of the `apiguard run` console output, after group 3 of block 5 (Q-26 and Q-10 change what is shown) | low | done 2026-10-09 |
| 5c | Cleanup | Q-63 | dead `src/tests/strategy.py`, empty validator, `build_zip.sh` excludes, `scripts/` lint, external-tool models location | very low | done 2026-10-09 |
| 5d | Engine and infrastructure leftovers | Q-61, Q-64, Q-62 | prerequisites between tests, parallel runs (not a goal), partial report (dropped); Q-34 moved to block 8 | low-medium | done 2026-10-10 |
| - | Integration guide | (step 2.2) | written on the fixed contract, short; tests the contract from the integrator's side; updated in block 8 | - | written 2026-10-09; owner review pending |
| 6 | Test quality review | Q-29, Q-32, Q-30 (code items), Q-24 (7.2 timeout), Q-50 (evidence per finding) | test by test: oracles, missing sub-tests, 1.1 `DELETE` last + `path_seed` check, 7.2 cleanup, evidence of 7.2, 4.1, 1.5 and config audits; notes from block 5: 1.4 may be GREY_BOX with an ordinary account, 6.4 split in two (changes test IDs: before 1.0.0), all `Set-Cookie` headers in the evidence of 1.6, 7.2 one finding per payload; map what each test produces and uses (tokens, created resources, repeated reads of the specification or gateway configuration) and share repeated work through `depends_on` (owner, Q-61) | high: one test at a time | to do |
| 7 | Second lab | Q-52 | cRAPI behind Kong, pinned, automated setup | low for the tool | to do |
| 6b | E2E suite | Q-51 | after the test review and the second lab: expected results with a stated basis (`lab-design` from the lab configuration, or `observed`) on both labs, ideally each test proven on a secure and a vulnerable variant | low | to do |
| 8 | Agnosticism | Q-18, Q-43, Q-38, Q-34 | per-test portability analysis on both labs, then remove Forgejo/Kong ties, protected Admin API | high | to do |
| - | Release 1.0.0 | (2.1, 2.2, 2.4) | owner review of the usage guides, integration guide and entry points, now stable; then release **1.0.0** (Q-25) | - | to do |
| 9 | Process | Q-16, Q-04, Q-13 | CI (`dev:check` + E2E), generated documentation with drift check | low | to do |
| 10b | Simplify adding a test | Q-56 | review the steps needed to add a native test | low | to do |
| 10 | Roadmap | Q-17 | rewrite as a product roadmap | none | to do |
| - | Knowledge translation | Q-33 (step 2.3) | methodology, tool decisions, design properties in English | none | to do |

Ordering rationale: the safety net first, so every later change is checked in minutes; risk-free work next; the
configuration structure before the contract and the test review (both touch test parameters); the contract (output
format) before the test review (output content). Revised 2026-10-09: a short cleanup (5c) first; the integration
guide right after the contract, to test it from the integrator's side before the test review; the second lab before
the E2E suite (expected results written once, for both labs) and before the agnosticism work; the owner review of
the guides last, when they are stable, just before 1.0.0; process and documentation work after the release.

## Phase 5 - Process

CI (Q-16), E2E test suite (Q-51), documentation generated from code with a drift check
(Q-04): blocks 6b and 9 of Phase 4.

## Log

| Date | What happened |
|---|---|
| 2026-10-05 | Docs restructured (phase A), reference, tests, architecture, contributor guides written; open questions logged |
| 2026-10-06 | Getting-started written; first run by the owner interrupted by hand (no reports); guide simplified; plan created |
| 2026-10-06 | Lab: credentials from `.env`, automated provisioning, TLS key permissions in `gen-certs.sh`; Q-40 and Q-41 closed by the owner |
| 2026-10-06 | Phase 1 closed; working order agreed (phases 2 and 3 interleaved) |
| 2026-10-06 | Lab creates every `path_seed` resource, names from `.env`; Q-46 closed by the owner; Q-47 logged |
| 2026-10-06 | `guides/usage/` written (configure a target, select tests, read the report), verified on the lab; Q-45 corrected; Q-48, Q-49, Q-50 logged |
| 2026-10-06 | New English `README.md`; `README.en.md` removed after checking every section against the new docs (only the CI/CD script is pending, for 2.2) |
| 2026-10-06 | `CONTRIBUTING.md` and `CHANGELOG.md` written; CLAUDE.md router and `maintainer-commands.md` cleanup pending (step 2.4) |
| 2026-10-06 | `CLAUDE.md` turned into a router (rules and exception hierarchy kept verbatim); `maintainer-commands.md` facts updated (personal sections kept) |
| 2026-10-06 | Owner decision: `CHANGELOG.md` added to the sdist; `docs/knowledge/` and `docs/project/` stay out of it (marked "repository only" in `docs/index.md`) |
| 2026-10-06 | Documentation audit: 56 files, 0 broken links/anchors; test metadata (18 tests), 97 config keys and defaults, CLI options, exit codes (130 verified with a real SIGINT) all match the code; no reference to closed questions or removed files |
| 2026-10-06 | Closed by the owner: Q-01 (Linux only; `Operating System :: MacOS` classifier removed, `compatibility.md` updated), Q-42 (Hatch is the only way to work from the repository; pip only in the integration guide, step 2.2), Q-07 (old `ADDING_tests.md` replaced by `add-a-native-test.md`; remaining drift in Q-37), Q-08 (new `README.md` links only user docs) |
| 2026-10-06 | Closed by the owner: Q-12 (verification is manual for now: `dev:check` + affected tests on the lab, as in `CONTRIBUTING.md`); the E2E suite is planned as Q-51 (group 3.D, with CI Q-16) |
| 2026-10-06 | Lab images pinned to exact versions (Forgejo 14.0.5, Kong 3.9.3, PostgreSQL 15.19; same image IDs as before), listed in `compatibility.md` "Test lab"; lab rebuilt from scratch, all 15 native tests give the same results. Closed by the owner: Q-03 (reference target of the guide: Forgejo + Kong); cRAPI as second official lab planned as Q-52 |
| 2026-10-06 | Closed by the owner: Q-14 (priority and strategy are independent: priority = severity, strategy = what the tester needs; `assessment-model.md` and `add-a-native-test.md` updated; methodology wording added to Q-33, warning messages already in Q-48) |
| 2026-10-06 | Decided by the owner: Q-37 (every native test always has a config model, even empty; checked in `dev:check` for developers, never at runtime), moved to 3.D. New Q-53: single definition of test parameters (move config models to `core/` as for external tools), after the E2E suite Q-51 |
| 2026-10-06 | Closed by the owner: Q-49 (`user_b` stays in configuration, `.env.example` and lab, reserved for tests comparing two users such as BOLA 2.2; documented in `configure-a-target.md` and `.env.example`) |
| 2026-10-06 | Closed by the owner: Q-09 (roadmap symbols describe tests, guarantee coverage stated separately; `ext.0.1.nuclei` is `[x]`, guarantee 0.1 covered in part, ffuf and katana planned). Verified first: nuclei alone on the lab, 3,328 templates, 193 s, 2 info results (Swagger exposed, correct; SSH of the host on port 22, out of scope, added to Q-29) |
| 2026-10-06 | Owner decision: Q-32 (missing methodology sub-tests) is not settled by labels; moved to 3.D with Q-29 as a per-test quality review in the code |
| 2026-10-06 | Owner decision: Q-25 (integration contract) not settled now: only a superficial pass and a draft policy; it touches code, so it becomes the first block of the code phase ("contract 1.0", with Q-20, Q-22, Q-23, Q-45, Q-50), followed by the integration guide (2.2) |
| 2026-10-06 | Closed by the owner: Q-02 (Python range = versions verified on the lab: `>=3.11,<3.15`; 3.11.14, 3.12.3, 3.13.9, 3.14.0 give identical results on the 15 native tests + `ext.1.5.sslyze`). Found during the check: `.env` is not read when the tool is installed with pip (Q-54, contract block); docs corrected to describe the real behaviour |
| 2026-10-06 | Decided by the owner: Q-15 (no exception to the dependency rule: fix the import in `external_tests/registry.py`, same class object; add an automatic layering check to `dev:check`, noted in Q-39); moved to the 3.D cleanup block |
| 2026-10-06 | Q-17: the roadmap conflict no longer exists (`roadmap.md` is the only source); light correction done (thesis wording removed, Milestone 2 = candidate tests, pointer to `plan.md`); full rewrite as product roadmap moved to the end of the 3.D planning |
| 2026-10-06 | Decided in principle by the owner: Q-10 (strategy = what the tester has: BLACK_BOX external user, GREY_BOX normal user, WHITE_BOX super user; labels must be true and the filter must apply to external tests too). Per-test label review and code in the contract 1.0 block, done carefully later; methodology alignment added to Q-33 |
| 2026-10-07 | Decided in principle by the owner: Q-24 (no config option without effect: remove `sslyze.extra_flags`; `ssrf_request_timeout_ms` decided during the 7.2 review); moved to 3.D. Stale docstring in `external_tests/base.py:851` added to Q-28 |
| 2026-10-07 | Decided in principle by the owner: Q-31 (redact only secret values with meaningful placeholders: role in `Authorization`, cookie attributes kept, fingerprint of the 1.4 token; bodies not redacted; every redaction justified and verified on the lab before/after); contract 1.0 block |
| 2026-10-07 | Closed by the owner: Q-47 (each test has its oracle; a reliable oracle's verdict is trusted; differences are reported and judged by the analyst; the 1.1 reads stay findings). Principle written in `assessment-model.md` ("Oracles and verdicts"), `read-the-report.md` reworded; read/write split in the 1.1 message added to Q-29 as an idea |
| 2026-10-07 | Q-11 deferred: the owner will ask how the product will be distributed; sslyze stays optional, fallback is leaving it out; the integration guide must warn about `[sslyze]`; decide with Q-05 |
| 2026-10-07 | Decided by the owner: Q-26 (absent = not selected, SKIP = something missing, never mixed; fix the code descriptions; evaluate a "not run by choice" list with reasons in every output, contract 1.0 block) |
| 2026-10-07 | Decided by the owner: Q-30 (keep behaviour; `path_seed` = volatile test resources that may receive any request, said everywhere; the tool does not restore deleted resources, the environment does: lab = full reset; 1.1 review: `DELETE` last + post-check of `path_seed` resources; 7.2 `fixed_path` cleanup or declaration). Docs updated: `configuration.md`, test 1.1 page, `first-assessment.md` troubleshooting |
| 2026-10-07 | Q-18 moved to 3.D (agnosticism block, after the cRAPI lab Q-52). Groups 3.B and 3.C done |
| 2026-10-07 | Phase 4 organised in 10 blocks (owner approved order); block 1 (safety net: E2E suite Q-51, tooling Q-39) starts with its detailed plan |
| 2026-10-07 | Owner decision: no E2E suite now (expected values would encode results that block 6 will change); Q-51 moved after block 6. Block 1 = development helper `scripts/compare_reports.py` (written and verified) + Q-39 tooling. `ruff format` configuration checked: adequate (line width 100 as the linter, double quotes, preview off); ruff 0.16 also formats Markdown code blocks, to be excluded |
| 2026-10-07 | Block 1 step 2 done: `ruff format` on 7 files (syntax trees identical to HEAD), `ruff format --check .` in `dev:check`, Markdown excluded; lab: 15 native tests and `ext.1.5.sslyze` unchanged (compare_reports: no differences) |
| 2026-10-07 | Block 1 step 3 done: Q-15 import fixed, `import-linter` with 3 contracts in `dev:check` (proved to catch the old import), docs updated; lab results unchanged |
| 2026-10-07 | Block 1 step 4 done: rule exceptions (test module numbers, `TypedDict` uses) and the full dependency rule written in `CLAUDE.md` and `coding-rules.md`. Block 1 done |
| 2026-10-07 | Block 2 done: 58 stale references, 13 contradicting comments, 3 SKIP descriptions, `sslyze.extra_flags` removed. Code identical apart from comments/docstrings in 29 files; string texts only in 5; one structural change (field removed). `dev:check` passes; lab: 15 native tests, `ext.1.5.sslyze` and external discovery unchanged |
| 2026-10-07 | Review of blocks 1-2: 48 doc references added in code all resolve; 2 comments made more precise (0.1 sampling, 2.1 statuses); no question ID left in code; CHANGELOG and the 1.5 oracle example corrected; the "issue 1 comes back as issue 2" claim verified on the lab, which also found Q-55 (setup misreports the recreated issue); lab reset, results back to baseline |
| 2026-10-07 | Block 3 decided by the owner: fix Q-35, Q-21 (stdout = template only, messages on stderr), Q-48, Q-55; remove Q-36 and Q-27 (container / HTTP tools kept as a future idea in the roadmap); Q-13 moved to block 9 |
| 2026-10-07 | Block 3 done: Q-35 (daemon fetch thread: hanging spec server → exit 10 after the timeout), Q-21 (`generate-seed` stdout = template only), Q-48 (warning texts), Q-55 (lab setup stops if issue/comment 1 were deleted), Q-36 and Q-27 removed (missing tool with `<TOOL>_SERVICE_URL` → SKIP, not ERROR); each reproduced before and verified after; lab results unchanged |
| 2026-10-07 | Regression check of blocks 1-3: full assessment (18 tests, external tools included) with the code before block 1 (`7fdd5a0`, separate venv) and with the current code on the same freshly reset lab: no differences in statuses, findings, messages, notes; external raw results identical apart from timestamps, scan time and the folder path. Also verified: pip-installed wheel (version, validate-config 0/10, generate-seed), JSON log output identical, Ctrl+C exit 130, `dev:check`. Closed by the owner: Q-15 (layering import fixed, import-linter), Q-19 (stale paths), Q-28 (contradicting comments), Q-35 (spec fetch hang), Q-21 (generate-seed stdout), Q-48 (warning texts), Q-55 (lab setup), Q-36 and Q-27 (unwired features removed) |
| 2026-10-07 | Q-53 decided by the owner: option C (one model per test in a dedicated package outside `core/`; external-tool models to follow later). New Q-56: review the steps needed to add a native test |
| 2026-10-07 | Block 4, Q-53 implemented: `src/test_config/` (lowest layer), one definition per test parameter, runtime copies removed; 48 parameters identical before/after, lab unchanged. Q-57 added (list parameters as tuples, separate safety check). Next: Q-37 |
| 2026-10-07 | Q-37 implemented: automatic wiring (`from_domains`, mismatches stop the run; owner chose this option B over the dev:check-only check of 2026-10-06), models for 0.1 (new parameter `method_probe_sample_size`, 1-100, default 10) and 0.3; the guide drops from 8 to 7 steps. Q-29 gains the 0.1 sampling limit (only 3 endpoints probed on Forgejo) |
| 2026-10-08 | Closed by the owner: Q-53 (single definition of test parameters in `src/test_config/`) and Q-37 (every native test has a model, automatic wiring). Block 4 done |
| 2026-10-08 | Q-57 moved from 10c to 4b, right after block 4: same files, and parameter types are part of the block 5 contract |
| 2026-10-08 | Block 4b, Q-57 implemented: 13 list parameters are tuples, helpers typed `Sequence`; the 7.2 body template dict kept (used only as a copy). Parameters and lab results unchanged |
| 2026-10-08 | Closed by the owner: Q-57 (list parameters as tuples). Block 4b done. Next: block 5 (contract 1.0), starting from Q-25 |
| 2026-10-08 | Block 5 order agreed: group 1 small contract defects (Q-20, Q-22, Q-23, Q-45, Q-54), group 2 design questions (Q-50, Q-44), group 3 decided in principle, implementation test by test (Q-10, Q-31, Q-26 list), group 4 Q-25 (contract list, `evidence.json` version, breaking-change signalling, 1.0.0). One question at a time; one commit per group. Contract split (draft, accepted roughly by the owner, to be confirmed in group 4): exit codes, report JSON, `evidence.json`, CLI, documented `config.yaml` keys; not log events, Python modules, message texts, `oracle_state`, HTML report |
| 2026-10-08 | Q-20 implemented (option B, owner): usage errors `2`, ERROR `3`; `ExitCode` enum is the single definition of the codes. Q-25 note: report format changes collected for one versioning in group 4; owner: schema versioning may restart from scratch |
| 2026-10-08 | Closed by the owner: Q-20 (usage errors `2`, ERROR `3`, `ExitCode` enum). Next: Q-22 |
| 2026-10-08 | Q-22 implemented (option A, owner): unknown `config.yaml` keys rejected at Phase 1 with a suggestion of the closest key; every validation error listed |
| 2026-10-08 | Closed by the owner: Q-22 (unknown config keys rejected, with suggestion). Next: Q-23 |
| 2026-10-08 | Q-23 implemented (owner): report JSON timestamp in UTC; HTML report shows it in the reader's time zone |
| 2026-10-08 | Closed by the owner: Q-23 (UTC in JSON, reader's time zone in HTML; browser rendering checked by the owner: `11:16:50 AM GMT+2`, tooltip `UTC: 2026-10-08T09:16:50...`). Next: Q-45 |
| 2026-10-08 | Q-45 implemented (owner): `test_ids` runs exactly the listed tests (`None` vs empty set in the registries). New Q-58 (a selection that runs nothing ends with exit 0; unknown or disabled IDs in `test_ids`), group 1 of block 5 |
| 2026-10-08 | Closed by the owner: Q-45 (`test_ids` runs exactly the listed tests). Q-58 kept for later in group 1. Next: Q-54 |
| 2026-10-08 | Q-54 implemented (owner): `.env` from the working directory plus `--env-file`; exported variables win. `run --help` exit codes fixed (Q-20 follow-up) |
| 2026-10-08 | Closed by the owner: Q-54 (`.env` from the working directory, `--env-file`). Next: Q-58, last of group 1 |
| 2026-10-08 | Q-58 implemented (owner): unknown or disabled `test_ids` entries and empty selections stop with exit 10 (one check after Phase 1, also in `validate-config`; empty selection in Phase 4). Exit codes logged as plain ints (Q-20 follow-up) |
| 2026-10-08 | Closed by the owner: Q-58. Block 5 group 1 done and committed (`0d80502`). Next: group 2 (Q-50, then Q-44) |
| 2026-10-08 | Q-50: rule decided by the owner (every HTTP finding points to its proof; an absence points to the last request; config audits without `evidence_ref` for now); implementation moved to block 6. 7.2 aggregation found to be a side effect of an earlier notes fix. Next: Q-44 |
| 2026-10-08 | Q-44 implemented (owner): SIGTERM handled like Ctrl+C (teardown, exit 143), progress `n/N` and tool timeout in test start lines, `external_tool_still_running` every 10 s; partial report on interruption moved to Q-26 (group 3) |
| 2026-10-08 | Q-44: cleanup messages on SIGTERM (owner). New Q-59 (readability of the `apiguard run` console output), to schedule |
| 2026-10-08 | Q-44: Ctrl+C and SIGTERM handled alike (owner): messages, repeated signals do not interrupt cleanup, process ends by the first signal (130/143). Q-59 placed after group 3 of block 5 |
| 2026-10-08 | Closed by the owner: Q-44. Block 5 group 2 done (Q-50 rule decided, implementation in block 6; Q-44 implemented). Next: group 3 (Q-10, Q-31, Q-26) |
| 2026-10-09 | Q-10 implemented (owner): strategies = what the tester has; 6 tests relabelled; external tests filtered by strategy; Phase 1 warnings mirror the SKIP conditions (two gaps of the old warnings fixed). Owner: an all-SKIP run stays CLEAN (no new question). `src/tests/strategy.py` found dead |
| 2026-10-09 | Q-10 completeness check before closing: stale strategy comments fixed in `config.yaml` (1.4, 1.5, 1.6, 6.2; comments only, `validate-config` 0), in `tool_config.py` (credentials docstrings), `test_config/domain_6.py`, `external_tests/registry.py` and `base.py` docstrings; external strategy filter defaults a missing `strategy` to BLACK_BOX like the report (a missing attribute already logs `external_test_registry_missing_classvar`). Real runs per strategy (nuclei and testssl off): BLACK 9 tests incl. sslyze, GREY 2.1 and 7.2 (2.1 PASS without 1.1), WHITE 1.4, 3.3, 4.2, 4.3, 6.4 (1.4 PASS without 1.1); statuses identical to the baseline; no warnings with the lab config; lab clean. Closed by the owner: Q-10. Next: Q-26 |
| 2026-10-09 | New Q-60 (incomplete test declarations dropped or defaulted silently), follow-up of Q-10, to do now in group 3 before Q-26 |
| 2026-10-09 | New Q-61 (policy for a dependency filtered out of the run), to schedule; owner: a rule is needed, not chance |
| 2026-10-09 | Q-60 implemented (owner): `src/core/test_metadata.py`, `TestDefinitionError`, check of all test declarations right after Phase 1 and in `validate-config`; priority range and ID format defined once in core. Gap found: unimportable test modules are skipped silently |
| 2026-10-09 | Closed by the owner: Q-60. Unimportable test modules: evaluated and rejected as over-engineering (a syntax error or a wrong import is caught by `ruff` and `mypy` in `dev:check`; optional libraries such as sslyze are imported lazily). Next: Q-26 |
| 2026-10-09 | Q-26 part 1 decided (owner): `not_run` list with closed reasons in JSON, HTML, console count. Part 2 (partial report on interruption) deferred as Q-62 |
| 2026-10-09 | Q-26 part 1 implemented: `not_run` with reasons in JSON, HTML and log; executed + not run = every test, verified on 5 configurations |
| 2026-10-09 | Q-26 extra check: no stale references to the removed debug events; HTML embedded data equals the JSON file (`not_run` included); two stale docstrings in `external_tests/registry.py` fixed (master switch, file naming); owner's full run with all tools: 18 run, 0 not run, lab clean. Closed by the owner: Q-26 (part 2 is Q-62). Next: Q-31 |
| 2026-10-09 | Group 3 (Q-10, Q-60, Q-26) overall check: stale texts fixed (`config.yaml` testssl comment, two `external_tools.py` descriptions: disabled tools now listed in `not_run`), `core/test_metadata.py` added to `CLAUDE.md` layout and `overview.md` tree, import graph in `overview.md` recomputed from the source (new `core/test_metadata` edges; `cli -> core/models`; `core/context` line completed). Owner's full run with every tool (2026-10-09) identical to the full run of 2026-10-07; both configs valid; `dev:check`; no broken links |
| 2026-10-09 | Q-31 implemented (owner): `SecretRegistry` with typed placeholders, applied at capture and in Phase 7; zero registered secrets in final and temporary outputs (were: 1.4 token and 7.2 webhook secrets in clear); 15 native tests identical before/after incl. evidence references. Open choice: 1.1 public probe values in `Authorization` |
| 2026-10-09 | Q-31: public probe values (owner, option b) shown as `[public probe] <value>`; safety net kept; cURL rebuild exact. Re-verified: 0 secrets, before/after identical |
| 2026-10-09 | Owner checked the HTML report: 1.1 malformed-token transactions show `[public probe] ...`, "copy as cURL" gives the exact request (`-H "authorization: Bearer"`, the empty-token variant). Closed by the owner: Q-31. Block 5 group 3 done (Q-10, Q-60, Q-26 part 1, Q-31). Next: group 4 (Q-25) |
| 2026-10-09 | Q-25 implemented (owner): interface contract in `compatibility.md` (A contract / B announced / C free), one version (tool semver, `output_schema_version` removed, `tool_version` in `evidence.json`), "Breaking:" + "Changed results" in the changelog, 1.0.0 after block 8; an intermediate release would be 0.2.0 |
| 2026-10-09 | Q-59 implemented (owner): console interface of `run` (header, one line per test with grouped findings, summary with report paths) through an engine `RunObserver`; default `--log-level warning`; levels reviewed (31 result events to `info`); technical log cleaned. 272 lines → 35 on the 15 native tests |
| 2026-10-09 | Q-59 follow-up: double Ctrl+C on a terminal tidied (live line stopped at cleanup start); `maintainer-commands.md` extended with the owner's testing commands |
| 2026-10-09 | Owner checked the console output and a double Ctrl+C on a real terminal (live line stops, message on its own line, cleanup done). Closed by the owner: Q-59. Block 5b done |
| 2026-10-09 | Closed by the owner: Q-25. Block 5 complete. Housekeeping: plan statuses updated (working order, block 5, phase 2 pages); Q-39 reduced to two items moved to new Q-63 (small leftovers not recorded elsewhere: dead `src/tests/strategy.py`, empty validator in `ExecutionConfig`, stale `build_zip.sh` excludes, external-tool models location); stale paths in Q-24 refreshed |
| 2026-10-09 | Closed by the owner: Q-39 (its two last items are in Q-63). Order of the next steps revised and agreed: 5c cleanup → integration guide → 6 (+ Q-61) → 7 → 6b → 8 → guides review and 1.0.0 → 9, 10b, 10, 2.3. "Where we are" section added at the top of the plan |
| 2026-10-09 | Block 5c implemented (Q-63): dead module, empty validator and re-export shim removed; `build_zip.sh` updated and its `-d` filter fixed; `scripts/` under ruff and mypy; external-tool models stay in `core` (documented). Incident: the owner's untracked `apiguard-assurance.zip` was overwritten and removed while testing the script |
| 2026-10-09 | Closed by the owner: Q-63. Block 5c done (owner: the lost zip is not needed). Next: integration guide (2.2) |
| 2026-10-09 | Integration guide planned with the owner (one page; no CI-specific example; every command verified in a pip install outside the repository). New Q-64 (two parallel runs: 1.4 ERROR, fixed token name), for block 6 |
| 2026-10-09 | Integration guide written (`docs/guides/integration/integrate-apiguard.md`), every command run as written in a wheel installed by pip in a fresh venv, from a working directory outside the repository: install, `validate-config` with `--env-file`, per-run output directory via `${APIGUARD_OUTPUT_DIR}`, JSON log run, the exit-code script (codes 1, 0, 3, 10, 143), the `jq` examples, `timeout` (124, or 143 with `--preserve-status`), external tools found on the PATH. Found and fixed: sslyze INFO lines broke the JSON log stream (5 plain-text lines; `sslyze` added to the noisy loggers, now 0). Linked from `docs/index.md` and README. Incident: the owner's existing `dist/` was removed while verifying `hatch build` |
| 2026-10-09 | Integration guide: section 2 rewritten for clarity (what the wheel does not contain, where `nuclei` and `testssl.sh` are looked for, `template_dir` example), after the owner's questions; owner agreed to proceed. Native tests identical to the baseline after the sslyze logger change. Next: block 6 |
| 2026-10-09 | Order revised by the owner: everything around the tests first (block 5d: Q-61, Q-64, Q-34, Q-62 to re-evaluate; then cRAPI lab with the infrastructure part of agnosticism; then process and documentation), the test review last, followed by the E2E suite and the missing sub-tests. Position of 1.0.0 to decide before the test review |
| 2026-10-09 | Q-61 implemented (owner): `depends_on` (data) and `requires_pass` (logic) applied by the engine, unmet prerequisite → SKIP with reason, unknown or self prerequisite → exit 10; the 1.4 and 2.1 dependency on 1.1 was not real and is removed; lab results identical. Owner's note for the test review: map what each test produces and uses |
| 2026-10-09 | Q-61 completeness check: no other reader of the dependency attributes (report, HTML, configuration); external test template updated (`requires_pass`, the two kinds explained); `dev:check`. Closed by the owner: Q-61. Next: Q-64 |
| 2026-10-09 | Closed by the owner: Q-64. Concurrent runs on the same target are not a goal (other tests, such as 4.1, would interfere anyway): no code change, the fixed token name and its pre-flight cleanup stay; the integration guide states one run at a time per target. Next: Q-34 |
| 2026-10-09 | Q-34 decided by the owner: moved to block 8 with Q-38 (Admin API protection depends on the gateway); implemented only against real protected Admin APIs in a lab. Limitation added to `reference/configuration.md` (`admin_api_url`). Next: re-evaluate Q-62 |
| 2026-10-10 | Closed by the owner: Q-62 (partial report on interruption), dropped: an interrupted assessment is incomplete and must be run again anyway; small gain against about a day of work on the signal path stabilised with Q-44 and new contract fields. Block 5d done. Next: plan block 7 (cRAPI lab) with the infrastructure part of block 8 |
