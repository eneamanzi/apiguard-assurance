# APIGuard Assurance - Roadmap

> **Audience:** project owner, contributors · **Status:** current (2026-10-27). What is still open, and what was
> deliberately dropped. The inventory of what exists is not here: the authoritative list of tests is the tool itself
> (`apiguard list-tests`) and the catalogue generated from it, [`../05-tests/README.md`](../05-tests/README.md).

- [Next work](#next-work)
- [Owner decisions](#owner-decisions)
- [Nothing else is planned](#nothing-else-is-planned)

## Next work

**Test-by-test review (every one of the 32).** Go through the suite one test at a time with the owner and decide, for
each, whether it earns its place, whether its oracle is sound, and whether every branch of it has been seen. A test
that does not earn it is removed, not weakened. How the pass is run, the per-test checklist and the progress:
[`test-review.md`](test-review.md) (a temporary file, deleted when the pass is over). One test per discussion, the
owner decides.

## Owner decisions

The only two things still open, and both are the owner's to settle, not work to pick up.

- **Licence (next to settle).** `pyproject.toml` leaves the licence unspecified on purpose. The choice depends on the
  university regulations and on how the product APIGuard is integrated into will be distributed; to settle before any
  public release or distribution.
- **Release 1.0.0.** After an owner review of the usage and integration guides and the entry points (README,
  CONTRIBUTING, index), tag 1.0.0 (the block-6 review changed test IDs and behaviour, so the release follows it).

## Nothing else is planned

The backlog left by the block-6 test review was closed on 2026-10-27, and nothing replaced it: no new guarantee, no
further external tool, no deeper sub-test. What was dropped, and where its substance now lives:

| What was dropped | Where it is now |
|---|---|
| Guarantees 2.3 and 6.3, the two without a test | Their catalogue entries, each with a **Coverage by the tool** block naming the scenarios that tests 2.2, 6.2 and 4.2 already cover and the one left out: [2.3](../06-knowledge/03-guarantees.md#23-destructive-operations-require-appropriate-privileges-p1-proposed-no-test), [6.3](../06-knowledge/03-guarantees.md#63-the-gateway-configuration-is-hardened-against-layer-7-exploits-p1-proposed-no-test) |
| jwt_tool, vegeta, katana, interactsh | The tool review, which says why each was considered: [`04-tool-decisions.md`](../06-knowledge/04-tool-decisions.md). The limit the out-of-band listener would have lifted is stated on the pages of tests [7.2](../05-tests/domain-7/7-2-ssrf-prevention.md) and [7.4](../05-tests/domain-7/7-4-webhook-verification.md) |
| Log content (5.1), behavioural alerts (5.2), an authenticated Schemathesis run and deep injection confirmation (3.1), password-change revocation (1.4), object derivation (2.2 / 2.5), breaker thresholds (4.3) | The **Limitations** section of each test's own page, as a permanent limit with what it would take, not as pending work |
| Running the external tools from containers; proposing `resources:` from the OpenAPI specification | Dropped outright: the first depends on how the product APIGuard is integrated into is built, the second was never more than an idea |

The nuclei connector is the one thing kept without a test: `ext.0.1.nuclei` was replaced by `ext.0.1.ffuf` in the
review, and the connector stays dormant, declared as such in `src/connectors/nuclei.py`.

## See also

- [`../05-tests/README.md`](../05-tests/README.md): the 32 tests, generated from their declarations.
- [`../03-reference/06-compatibility.md`](../03-reference/06-compatibility.md#external-tools): the external tools,
  their pinned versions, who installs them and which test uses them.
- [`../06-knowledge/04-tool-decisions.md`](../06-knowledge/04-tool-decisions.md): which tool was considered for which
  guarantee, and why it was chosen or left out.
