# Experiments

The experiments of the paper, each run by one command on the labs (`test-environments/`), each writing its result
in its own `results/` folder, named after the commit it ran on. They measure the tool; they are not part of it
(nothing in `src/` imports them). What they share (the labs, their reset, a run of the tool with a live line, the
naming of a result) is `shared/experiment.py`.

| Experiment | Question | Command | Folder |
|---|---|---|---|
| E1, oracle validation | Does every test record, in each situation, the case its oracle declares? | `hatch run dev:e1-oracle-validation` | [`e1-oracle-validation/`](e1-oracle-validation/README.md) |
| E2, complete run | What does each test give on each lab as built? | `hatch run dev:e2-complete-run` | [`e2-complete-run/`](e2-complete-run/README.md) |
| E3, crAPI challenges | Which of the weaknesses crAPI declares does the tool find? | `hatch run dev:e3-crapi-challenges` | [`e3-crapi-challenges/`](e3-crapi-challenges/README.md) |

A **campaign** (every case or lab, on a clean commit) is the evidence a paper cites: it starts from freshly reset
labs (their data is lost: the full reset of the maintainer commands), its result is committed and replaces the
previous one, git keeping the history. A **trial** (only some tests or labs: `-partial`; a working tree with changes:
`-dirty`) runs on the labs as they are and stays local, the latest only. The raw reports of each run (`*-runs/`)
stay local. The test pages state the latest campaigns: the Validation section of each test (E1, E2) and the crAPI
section of the compatibility page (E3), rewritten by `hatch run dev:gen`.

The order for a paper: commit, then E1 and E2 (each resets the labs it uses; hours), then E3 (it reads E2's crAPI run
and runs nothing), then `hatch run dev:gen` and a commit of the results and the pages.
