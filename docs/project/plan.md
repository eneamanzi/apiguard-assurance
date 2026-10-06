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
| 8 | 3.C questions where Claude leans to a code change: Q-10, Q-24, Q-31, Q-47; then Q-11, Q-18, Q-26, Q-30 | to do |
| 9 | 3.D Questions that need code: discuss and plan (first the contract 1.0 block Q-25 + Q-20, Q-22, Q-23, Q-45, Q-50, Q-54, then 2.2 `guides/integration/`; small bugs Q-35, Q-21, Q-48; comments Q-19, Q-28; second lab Q-52, then agnosticism Q-43, Q-38, Q-18, Q-34; process) | to do |
| 10 | 2.3 `knowledge/` translation (with Q-33) | to do |

Phase 4 (implementation) follows the decisions of 3.C and 3.D; Phase 5 with the process questions of 3.D.

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
| 3.C | "Document as is" or "change the code" | Q-10, Q-11, Q-18, Q-24, Q-26, Q-30, Q-31, Q-47 | a question whose decision needs code moves to 3.D |
| 3.D | Code or process changes | **first block, "contract 1.0": Q-25 with Q-20, Q-22, Q-23, Q-45, Q-50, Q-54 (review in depth, after the 3.C decisions)**; Q-20, Q-21, Q-22, Q-23, Q-35, Q-44, Q-45, Q-48, Q-50 (behaviour); Q-19, Q-28, Q-15 (comments, stale paths, one import: cleanup block); Q-27, Q-34, Q-36, Q-38, Q-43 (features); Q-17 (rewrite `roadmap.md` as a product roadmap, last step of the 3.D planning); Q-04, Q-13, Q-16, Q-39, Q-51 (tooling, CI, E2E suite); Q-29 + Q-32 (per-test quality review: weak oracles and missing sub-tests, test by test); Q-53 then Q-37 (single definition of test parameters, every test has a config model; after Q-51); Q-52 (second lab, cRAPI: before the agnosticism work) | discussed and planned after 3.B and 3.C |
| - | Deferred | Q-05, Q-06 | licence, security policy |

## Phase 4 - Implement the decisions

After each group of Phase 3 is decided, in the same group order. Each change: Claude states the files and the plan, waits for the go,
changes them, and gives the owner a test to run (usually: reset, steps 0-5 of the first assessment, compare the
report). The documentation page affected is updated in the same change.

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
