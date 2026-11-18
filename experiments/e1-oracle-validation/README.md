# E1: validation of the oracles

This folder produces, by script, every case of every test's oracle on the labs, and compares what each run records
with what the oracle declares. It is not part of the tool (nothing in `src/` imports it): it validates the tool at
one commit, so that the evidence of E1 can be produced again by anyone with the labs.

## What a case is

A case is one row of the oracle a test declares in its code: the `OracleCase` entries of `info = TestInfo(oracle=...)`
in the test's module (`_ORACLE`), from which the Oracle section of its page is generated. A row is a situation in
words (`when`) and the judgement it gives, in code: outcome, detail and, for a violation, confidence. The judgement
is binding: `_record` refuses one the oracle does not declare, so the code can only give its declared rows; which
row a situation gives is decided by the test's branches, and that is what a run checks. A family (`SERVED_AS_<kind>`) gives one case per member.
Two shared rules add cases to the tests they apply to: `CONCEPT_NOT_ACCESSIBLE` for a test that reads a gateway
concept, and the answers that say nothing (`UPSTREAM_UNAVAILABLE`, `RATE_LIMITED`, `SERVER_ERROR`, `NO_RESPONSE`)
on any sub-test that does not judge them. The list comes from the code, never from this folder: no one chooses
which cases exist.

## The files

- `cases/<test>.yaml`, one per test, every case of the test, grouped under `sub_tests` by sub-test in the order the
  test declares them (as the Oracle section of its page); the answers that say nothing, which hold for any sub-test, last,
  under `any_sub_test`. Each case has:
  - copied from the code, never edited by hand: `id` (outcome, detail, confidence), `situation` (the sentence of
    the page's Oracle section), `expected` (outcome, detail, confidence);
  - written by us: `how` (how the situation is produced, in words), `lab`, `variant` (`none` for the lab as built,
    else a name in `variants/<lab>.yaml`), `config` (changes to the tool's configuration, optional); or, for a case
    no lab can give, `not_producible` with its `group` (`code`, `gateway`, `environment`, `decision`) and `reason`.
- `variants/<lab>.yaml`, one per lab (`forgejo-kong`, `crapi-kong`, `forgejo-apisix`): each variant is one
  temporary change to that lab, with `what` it does in words and the `change` the runner applies and undoes.

## The commands

- `hatch run dev:python experiments/e1-oracle-validation/sync.py`: brings the case files in line with the code. It adds the cases the code declares and
  a file lacks (to fill), refreshes the copied fields, removes the cases the code no longer declares and names them.
  It never deletes the fields we write; when the code changes the situation of a case already filled, it marks the
  case `review`, and `dev:check` fails until someone checks its `how` and removes the mark. A changed outcome,
  detail or confidence is another case: the old one is removed (its `how` printed), the new one is to fill.
  The cases are in the order of the page's Oracle section.
- `hatch run dev:python experiments/e1-oracle-validation/check.py`: the alignment check, part of `hatch run dev:check` (with
  `--complete`). Each file must hold exactly the
  code's cases with the copied fields equal to it, and each variant named must exist. So code, test pages (generated
  from the code by `dev:gen`) and these files cannot drift apart: a changed oracle fails `dev:check` until
  `sync.py` is run and the new case is filled. With `--complete` (as `dev:check` runs it) it also fails while a case
  is left to fill: no oracle row without a way to produce it, or the reason there is none.
- `hatch run dev:e1-oracle-validation` (labs needed): a campaign first resets the three labs; then, for each
  variant, it records the lab's state, applies the change, runs the tests whose cases need it, reads the cases each
  run produced (`sub_tests[].cases` of the report), undoes the change and checks the lab is back to the recorded
  state (it stops if not). While a group runs, one live line names the test reached and the time elapsed. Do not
  edit `cases/` or `variants/` while it runs: they are read group by group. `--test 3.3 4.2` runs only those tests,
  `--lab forgejo-kong` only that lab's cases: a trial, on the labs as they are.
- `results/`: per run, a readable Markdown (test by test in the order of the pages: each case with expected,
  observed, how it was produced, `OK` or `DIFFERENT`) and a JSON with the same for the counts, naming the commit and
  the tool version. Campaigns and trials are kept as [`experiments/README.md`](../README.md) says; the Validation
  section of each test page is generated from the latest campaign.

## Where each field comes from

| Field | Written by | Checked by |
|---|---|---|
| `id`, `situation`, `expected` | `sync.py`, from the code | `check.py`: equal to the code |
| `how`, `lab`, `variant`, `config`, `spec` | by hand | `run.py`: the variant gives the expected case on the lab |
| `not_producible` | by hand, with the page's reason | review only: no run can show a case cannot be produced |
| `variants/<lab>.yaml` | by hand | `run.py`: applied, undone, the lab checked identical |

`how` is words: a run proves the variant gives the case, not that `how` describes it well.

## What it proves, and what it does not

A run shows that each variant made the code record the expected case: coherence between the situation and the
declared oracle. Whether the declared judgement is the right one (correctness) rests on the standards each test
cites, on the reference responses, on E3 and on independent reviews, not on this folder.
