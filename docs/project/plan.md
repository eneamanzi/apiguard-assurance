# Operational Plan

> **Audience:** project owner, Claude Code · **Status:** active (created 2026-10-06) · Single source for "what do we
> do next". Update the status column as steps are completed.

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
| 9 | 3.D Code work, block by block (see Phase 4 below): each block is planned in detail with the owner, then implemented one change at a time | in progress (block 1) |
| 10 | 2.3 `knowledge/` translation (with Q-33) | to do |

Phase 4 (implementation) follows the block order below; Phase 5 is block 9.

## Phase 2 - Finish the documentation

Each step: Claude writes the section from verified facts, the owner reads it as a user (is it clear, can I follow
it), Claude fixes, owner commits.

| # | Step | Content | Status |
|---|---|---|---|
| 2.1 | `guides/usage/` | configure a target, select tests, read the report | to do |
| 2.2 | `guides/integration/` | run in CI, consume the JSON report, secrets and deployment, install the package with pip. The old CI/CD script is in `git show b8cdd9e:README.en.md` (section "CI/CD pipeline integration", lines 335-354; it has a known defect, see `docs-inventory.md`) | to do |
| 2.3 | `knowledge/` translation | methodology, tool decisions, design properties in English; background as a summary | to do |
| 2.4 | Entry points | new README (English only, Hatch, Linux), CONTRIBUTING, CHANGELOG, `docs/index.md`, CLAUDE.md as a thin router, clean `maintainer-commands.md`, remove `README.en.md` duplicate | to do |

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
| 5 | Contract 1.0 | Q-25, Q-20, Q-22, Q-23, Q-45, Q-58, Q-50, Q-54, Q-10, Q-31, Q-26 ("not run by choice" list), Q-44 | everything an integrator sees; then the stability policy | medium-high | to do |
| - | Integration guide | (step 2.2) | written on the fixed contract | - | to do |
| 6 | Test quality review | Q-29, Q-32, Q-30 (code items), Q-24 (7.2 timeout) | test by test: oracles, missing sub-tests, 1.1 `DELETE` last + `path_seed` check, 7.2 cleanup | high: one test at a time | to do |
| 7 | Second lab | Q-52 | cRAPI behind Kong, pinned, automated setup | low for the tool | to do |
| 8 | Agnosticism | Q-18, Q-43, Q-38, Q-34 | per-test portability analysis on both labs, then remove Forgejo/Kong ties, protected Admin API | high | to do |
| 6b | E2E suite | Q-51 | after the test review: expected results with a stated basis (`lab-design` from the lab configuration, or `observed`), ideally each test proven on a secure and a vulnerable lab variant | low | to do |
| 9 | Process | Q-16, Q-04, Q-13 | CI (`dev:check` + E2E), generated documentation with drift check | low | to do |
| 10b | Simplify adding a test | Q-56 | review the steps needed to add a native test (after block 4) | low | to do |
| 10 | Roadmap | Q-17 | rewrite as a product roadmap | none | to do |

Ordering rationale: the safety net first, so every later change is checked in minutes; risk-free work next; the
configuration structure before the contract and the test review (both touch test parameters); block 4b right after block 4 (same
models, and parameter types are part of the contract); the contract (output
format) before the test review (output content); the second lab before the agnosticism work. Block 9 may move right
after block 1; block 7 is independent.

## Phase 5 - Process

CI (Q-16), E2E test suite (Q-51), documentation generated from code with a drift check
(Q-04). Planned after the first decisions of Phase 3.6.

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
