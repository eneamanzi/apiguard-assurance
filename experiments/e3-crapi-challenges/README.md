# E3: crAPI challenges

OWASP crAPI is vulnerable by design and publishes the weaknesses it was built to contain: the expected values are
not ours. E3 reads each of crAPI's challenges in E2's run on the crAPI lab.

- `challenges.yaml`: crAPI's 18 numbered challenges, number, title and category verbatim from crAPI's
  `docs/challenges.md`, each with the rule that reads it, written before the run: **caught** (a finding of the
  named test whose title names the challenge's endpoint), **named, not exploited** (a case the test records when it
  finds the operation and does not send it), **attempted** (the test could not decide, INCONCLUSIVE), **missed**
  (also when no implemented test can reach it); or **absent from the lab**, with the reason (the feature is not
  deployed).
- `hatch run dev:e3-crapi-challenges`: runs nothing; reads the latest E2 result and writes `results/`: every
  challenge with its verdict and what shows it, and the counts over every challenge and over those in scope. It is a
  campaign when E2's result is one and the working tree is clean.

The crAPI section of the compatibility page is generated from the latest campaign.
