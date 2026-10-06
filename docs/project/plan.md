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
| 1.2 | Follow `installation.md` then `first-assessment.md` literally, from the official folder, **without interrupting the run** | owner | exit code `1`, three report files in `outputs/`, five `200` in the readiness check; every unclear point noted | to do |
| 1.3 | Fix the pages from the notes of 1.2, mark them verified | Claude | owner confirms | to do |
| 1.4 | Commit | owner | `git status` clean | to do |

## Phase 2 - Finish the documentation

Each step: Claude writes the section from verified facts, the owner reads it as a user (is it clear, can I follow
it), Claude fixes, owner commits.

| # | Step | Content | Status |
|---|---|---|---|
| 2.1 | `guides/usage/` | configure a target, select tests, read the report | to do |
| 2.2 | `guides/integration/` | run in CI, consume the JSON report, secrets and deployment, install the package with pip | to do |
| 2.3 | `knowledge/` translation | methodology, tool decisions, design properties in English; background as a summary | to do |
| 2.4 | Entry points | new README (English only, Hatch, Linux), CONTRIBUTING, CHANGELOG, `docs/index.md`, CLAUDE.md as a thin router, clean `maintainer-commands.md`, remove `README.en.md` duplicate | to do |

## Phase 3 - Decide the open questions

`OPEN_QUESTIONS.md` holds every doubt found so far. One session per group: Claude presents each question with
the evidence and 2-3 options, the owner decides, the decision is written in the entry. **No code is changed in
this phase**; decisions feed Phase 4.

| # | Group | Questions | Why this order |
|---|---|---|---|
| 3.1 | Test lab | Q-46 | small, last link between the lab and `config.yaml` |
| 3.2 | Product contract for integration | Q-25, Q-20, Q-23, Q-31, Q-30, Q-11, Q-34 | needed before the integration guide is final |
| 3.3 | Agnosticism | Q-43, Q-18, Q-38, Q-03 | defines how the tool must work on other targets |
| 3.4 | Test behaviour | Q-29, Q-10, Q-26, Q-22, Q-24, Q-44, Q-45 | oracle and selection rules |
| 3.5 | Bugs and cleanup | Q-35, Q-36, Q-21, Q-27, Q-28, Q-19, Q-37, Q-39, Q-07, Q-08 | mostly confirmations |
| 3.6 | Process | Q-12, Q-16, Q-04, Q-13, Q-02, Q-42 | tests, CI, generated docs |
| 3.7 | Research and roadmap | Q-09, Q-14, Q-15, Q-17, Q-32, Q-33 | thesis material and future work |
| - | Deferred | Q-05, Q-06 | licence, security policy |

## Phase 4 - Implement the decisions

Only after Phase 3, in the same group order. Each change: Claude states the files and the plan, waits for the go,
changes them, and gives the owner a test to run (usually: reset, steps 0-5 of the first assessment, compare the
report). The documentation page affected is updated in the same change.

## Phase 5 - Process

CI (Q-16), verification procedure or test suite (Q-12), documentation generated from code with a drift check
(Q-04). Planned after the first decisions of Phase 3.6.

## Log

| Date | What happened |
|---|---|
| 2026-10-05 | Docs restructured (phase A), reference, tests, architecture, contributor guides written; open questions logged |
| 2026-10-06 | Getting-started written; first run by the owner interrupted by hand (no reports); guide simplified; plan created |
| 2026-10-06 | Lab: credentials from `.env`, automated provisioning, TLS key permissions in `gen-certs.sh`; Q-40 and Q-41 closed by the owner |
