# Validation of the oracles (E1)

This folder produces, by script, every case of every test's oracle on the labs, and compares what each run records
with what the oracle declares. It is not part of the tool (nothing in `src/` imports it): it validates the tool at
one commit, so that the evidence of E1 can be produced again by anyone with the labs.

## What a case is

A case is one row of the oracle a test declares in its code (section 6 of its page): a situation and the judgement
it gives, outcome, detail and, for a violation, confidence. A family (`SERVED_AS_<kind>`) gives one case per member.
Two shared rules add cases to the tests they apply to: `CONCEPT_NOT_ACCESSIBLE` for a test that reads a gateway
concept, and the answers that say nothing (`UPSTREAM_UNAVAILABLE`, `RATE_LIMITED`, `SERVER_ERROR`, `NO_RESPONSE`)
on any sub-test that does not judge them. The list comes from the code, never from this folder: no one chooses
which cases exist.

## The files

- `cases/<test>.yaml`, one per test, every case of the test, grouped under `sub_tests` by sub-test in the order the
  test declares them (as section 6 of its page); the answers that say nothing, which hold for any sub-test, last,
  under `any_sub_test`. Each case has:
  - copied from the code, never edited by hand: `id` (outcome, detail, confidence), `situation` (the sentence of
    the page's section 6), `expected` (outcome, detail, confidence);
  - written by us: `how` (how the situation is produced, in words), `lab`, `variant` (`none` for the lab as built,
    else a name in `variants/<lab>.yaml`), `config` (changes to the tool's configuration, optional); or, for a case
    no lab can give, `not_producible` with its `group` (`code`, `gateway`, `environment`, `decision`) and `reason`.
- `variants/<lab>.yaml`, one per lab (`forgejo-kong`, `crapi-kong`, `forgejo-apisix`): each variant is one
  temporary change to that lab, with `what` it does in words and the `change` the runner applies and undoes.

## The commands

- `python validation/sync.py`: brings the case files in line with the code. It adds the cases the code declares and
  a file lacks (to fill), refreshes the copied fields, removes the cases the code no longer declares and names them.
  It never deletes the fields we write; when the code changes the situation of a case already filled, it marks the
  case `review`, and `dev:check` fails until someone checks its `how` and removes the mark. A changed outcome,
  detail or confidence is another case: the old one is removed (its `how` printed), the new one is to fill.
  The cases are in the order of the page's section 6.
- `python validation/check.py`: the alignment check, part of `hatch run dev:check`. Each file must hold exactly the
  code's cases with the copied fields equal to it, and each variant named must exist. So code, test pages (generated
  from the code by `dev:gen`) and these files cannot drift apart: a changed oracle fails `dev:check` until
  `sync.py` is run and the new case is filled. With `--complete` it also fails while a case is left to fill.
- `python validation/run.py` (labs needed): for each variant, records the lab's state, applies the change, runs the
  tests whose cases need it, reads the cases each run produced (`sub_tests[].cases` of the report), undoes the
  change, and checks the lab is back to the recorded state (it stops if not). It writes a readable result, per test
  every case with expected, observed, variant and OK or DIFFERENT, and the same in JSON for the counts; both name
  the commit, whether the working tree had changes and the tool version. The paper cites a run on a clean commit.
  Options: `--test 3.3 4.2` only those tests, `--lab forgejo-kong` only that lab's cases, `--reset crapi-kong`
  reset those labs first (their data is lost: the documented full reset), as a campaign for the paper does.
- `validation/results/`: one result per campaign, `<date>-<time>-<commit>[-dirty].md` (readable, in the order of the
  pages) and `.json` (the same, for the counts). The raw reports of each run (`*-runs/`) stay local, not committed.

## What it proves, and what it does not

A run shows that each variant made the code record the expected case: coherence between the situation and the
declared oracle. Whether the declared judgement is the right one (correctness) rests on the standards each test
cites, on the reference responses, on E3 and on independent reviews, not on this folder.
