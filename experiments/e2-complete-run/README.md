# E2: complete run

Every test on each lab as built: the lab reset, then one run of the tool with the lab's committed configuration and
nothing else. It answers what the tool says about each lab, test by test, and what the run costs.

- `hatch run dev:e2-complete-run` (labs needed): resets each lab and runs every test on it, external tests included.
  `--lab crapi-kong` runs only that lab: a trial.
- `finding_origins.yaml`: where each kind of finding comes from, a judgement written by hand: the **application**
  (a weakness of the API, found behind any gateway), the **lab** (how the lab is built: its gateway configuration,
  its network, what was added for the tests), the **specification** (the API does what its specification does not
  say, not a weakness), or **both** (a guarantee the API or the gateway can enforce, and neither does in the lab: a
  limit on requests, on body size, on failed logins). One rule per kind of finding: its test, a regular expression
  on its title, the labs it holds on, the origin and why. E2 applies the first rule that matches each finding and
  counts them by origin; a finding no rule covers is **to classify**, and the run says so. After adding a rule,
  `hatch run dev:e2-complete-run --classify` reads the origins of the latest result again, without running.
- `results/`: a readable Markdown with each lab's run (statuses, findings, duration, requests), every test on every
  lab (its status, the number of its findings, the reason of a SKIP), the findings by origin, and each lab's
  findings with their origin and why; a JSON with the same
  per test (status, coverage, findings, the cases judged, duration, requests). The raw report of each lab is in
  `<stamp>-runs/<lab>/`, local.

The Results on the labs part of each test page's Validation section is generated from the latest campaign; E3 reads
crAPI's run from it.
