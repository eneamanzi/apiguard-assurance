# E2: complete run

Every test on each lab as built: the lab reset, then one run of the tool with the lab's committed configuration and
nothing else. It answers what the tool says about each lab, test by test, and what the run costs.

- `hatch run dev:e2-complete-run` (labs needed): resets each lab and runs every test on it, external tests included.
  `--lab crapi-kong` runs only that lab: a trial.
- `results/`: a readable Markdown with each lab's run (statuses, findings, duration, requests), every test on every
  lab (its status, the number of its findings, the reason of a SKIP) and each lab's findings; a JSON with the same
  per test (status, coverage, findings, the cases judged, duration, requests). The raw report of each lab is in
  `<stamp>-runs/<lab>/`, local.

The Results on the labs part of each test page's Validation section is generated from the latest campaign; E3 reads
crAPI's run from it.
