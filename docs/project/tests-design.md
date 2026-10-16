# Test Declaration - Design (block 10b, Q-56)

> **Audience:** project owner, Claude Code · **Status:** working file, to decide with the owner point by point; when
> the work is done its conclusions go to `docs/architecture/design-decisions.md` and this file is removed ·
> **Created:** 2026-10-15

## 1. Why

Adding a test should mean writing the test and its page. Today it means touching up to ten places, six of which
nothing checks, and the information copied by hand has already drifted. The question (owner, 2026-10-15): with a
blank sheet, how would a designer make a test a self-contained unit, before the test review adds and rewrites many
tests (block 6) and before CI and generated documentation (block 9)? The answer must hold for an enterprise tool:
not to be redone later.

## 2. What we want

| # | Goal | Measured by |
|---|---|---|
| G1 | A new test is **one module plus its page**; nothing else written by hand | the trial of section 3 repeated: files touched |
| G2 | **One source for every fact** about a test: its identity (ID, name, priority, strategy, CWE, tags, prerequisites), its parameters (name, type, default, constraints, description), what it needs | no fact written twice |
| G3 | **Every mistake caught early and clearly**: by `validate-config` or `dev:check`, with a message naming the test and the fix; never a raw Pydantic error at run time, never silence | the mistakes of section 3, each tried |
| G4 | **Static typing kept**: a test reads its parameters with their types, checked by mypy | mypy on a misspelled parameter |
| G5 | **The user's configuration unchanged** (`tests.domain_<D>.test_<D>_<N>.<param>`), unless a change is clearly better | keys of the three labs and `config.example.yaml` |
| G6 | **One mechanism for native and external tests** | the same declaration in both |
| G7 | **The dependency rules kept or improved** (`lint-imports`) | the contracts |
| G8 | **Report, evidence and exit codes unchanged** | three labs identical to their references |

Out of scope: what a test checks (the test review, block 6); generated documentation for the CLI and the rest of the
configuration (block 9 extends the mechanism chosen here).

## 3. Facts

### 3.1 Trial in a scratch copy (2026-10-15)

A trial test 2.9 (one parameter) and 5.9 (none) were added following `add-a-native-test.md`.

| # | Place | What | Forgotten |
|---|---|---|---|
| 1 | `src/test_config/domain_<D>.py` | parameter model, and a field in the domain container | the test fails when it reads its parameters; a test without parameters works without a model, although the rule says every test has one |
| 2 | `src/test_config/runtime.py` | import and field `test_<D>_<N>`: a **copy** of step 1 | `validate-config` says valid; every run stops at Phase 3 with a raw Pydantic error (`extra_forbidden ... test_2_9`) |
| 3 | `src/tests/domain_<D>/test_<D>_<N>_<name>.py` | the test (nine class attributes, checked by a hand-written validator) | - |
| 4 | `config.example.yaml` | commented parameter block | only `dev:check` notices; the tool works |
| 5 | `docs/tests/<domain>/<test>.md` | the page, whose header table repeats ID, name, domain, priority, strategy, CWE | nothing notices |
| 6 | `docs/tests/README.md` | catalogue row (ID, name, priority, strategy, CWE, needs) | nothing notices |
| 7 | `docs/reference/configuration.md` | parameter table, with descriptions written again | nothing notices |
| 8 | `docs/architecture/assessment-model.md` | the ID in the lists by strategy and by priority | nothing notices |
| 9 | `docs/reference/compatibility.md` | row in "Test portability" | nothing notices |
| 10 | `docs/project/roadmap.md` | row in the tests overview | nothing notices |

A test in a domain without parameters yet (domain 5) also needs `src/test_config/domain_5.py` and a field in
`src/config/schema/tests_config.py`. The test folders of the eight domains already exist.

### 3.2 Other facts

- **Drift has happened**: the catalogue still says 1.4 needs "Forgejo" and the audits an "Admin API (Kong)"; the
  descriptions in `configuration.md` are worded differently from the models' `description`; the guide names a
  `config.yaml` that no longer exists.
- **The metadata are nine separate class attributes** (`test_id`, `test_name`, `domain`, `priority`, `strategy`,
  `depends_on`, `requires_pass`, `tags`, `cwe_id`; external tests also `tool_name`), validated by a hand-written
  function (`src/core/test_metadata.py`, `metadata_problems`, about 90 lines): what Pydantic does everywhere else in
  the tool. `domain` repeats the first number of `test_id` and is checked to match it.
- **Two base classes repeat the same plumbing**: `BaseTest` and `ExternalToolTest` each define `_metadata_kwargs`,
  `_make_pass`, `_make_fail`, `_make_skip`, `_make_error`.
- **Test IDs cannot be YAML keys**: YAML reads `2.10` as the number 2.1, so `tests: {2.1: ..., 2.10: ...}` would
  collide (checked with PyYAML).
- Fifteen native tests read their parameters as `target.tests_config.test_<D>_<N>`; every test can read every other
  test's parameters.
- 17 test modules: 15 native, 2 external (`ext_test_0_1`, `ext_test_1_5`, the latter with two tools).
- **The report reads only the results** (`src/report/builder.py`: `result.test_id`, `result.priority`, ...), never
  the test classes: the declaration can change without touching the report (G8).

### 3.3 Cascade effects (read in the code, 2026-10-15)

1. **Phase order.** `tests:` is validated in Phase 1 with the rest of `ToolConfig`; the tests are discovered only in
   Phase 4 (`src/engine.py:934`), after the specification download. Parameter models declared by the tests need the
   discovery first.
2. **The configuration schema knows test 7.2.** `ToolConfig.test_7_2_injection_placeholders`
   (`src/config/schema/tool_config.py:756`) checks 7.2's templates against `resources` and imports 7.2's placeholder
   names from `src/test_config/domain_7.py`.
3. **The Kong adapter reads parameters of 3.3 and 4.3.** `src/engine.py:809-810` passes `signing_config` and
   `breaker_config`; `src/core/gateway/kong.py:212-242` uses `plugin_names`, `field_clock_skew`, `field_algorithms`,
   `field_validate_body` (3.3) and `accepted_cb_plugin_names` (4.3). They describe Kong plugins, not the tests'
   oracles; the APISIX adapter ignores them. `core/gateway/base.py` imports `src.test_config` for them. None of the
   five keys is set in the three lab configurations; all are in `config.example.yaml`.
4. **The dependency rule.** `src.test_config` is the lowest layer and imports nothing from `src/`, so a parameter
   model cannot use `core` helpers (`src/core/templating.py:26` notes the workaround).
5. **Tools that walk the schema.** `scripts/check_config_keys.py` walks `ToolConfig`, `tests:` included.
6. **`hatch run dev:docs`** (pydoc-markdown) names `src.config.schema.tests_config` in its module list.
7. **3.3 carries a Kong sentinel**: `clock_skew_unconfigured_value` (Kong's `clock_skew: 0` means no limit) is read
   by the test itself (`test_3_3_hmac_config_audit.py:631`), not by the adapter: Kong knowledge in a test (6.6).
8. **Documentation naming `test_config`**: `overview.md`, `data-model.md`, `add-a-native-test.md`, `coding-rules.md`,
   `configuration.md`, CLAUDE.md, CHANGELOG (history, kept).

## 4. Prior art

Mature tools with many independent checks make **each check carry its own description**, and generate the rest:

- **ESLint**: a rule is an object with a `meta` block (type, docs, `schema` of its options) next to its logic; the
  options are validated against that schema and the rule pages are generated.
- **Ruff**: every rule's documentation page is generated from the rule's definition in the code
  (`crates/ruff_dev/src/generate_docs.rs`); `ruff rule --all --output-format json` lists them.
- **Bandit** (1.9.4, read in the installed code): a check declares its ID with `@test_id` and its parameters with
  `@takes_config`, its module gives their defaults (`gen_config`), and `bandit-config-generator` builds the
  configuration file from every check.
- **Pylint**: a checker declares its options; `--generate-toml-config` writes the configuration from them.
- **Nuclei**: every template carries its metadata in an `info` block (name, severity, description, references,
  tags); runs are filtered by them.

None keeps the parameters of a check in a central file apart from the check.

## 5. Direction

### 5.1 Alternatives

| Option | What | Solves | Leaves |
|---|---|---|---|
| A. Keep the places, add consistency checks | a script compares the copies | drift is detected | nine places to write per test |
| B. Generate only the documentation | catalogue and tables generated, `src/test_config/` kept | documentation drift | the `runtime.py` trap, two code places per test, every test reading every test's parameters, `core` and `config` knowing tests |
| **C. Self-contained test + generated documentation** | everything about a test in its module, the rest generated | all goals | parameters of one domain spread over its test modules (read together in the generated `configuration.md` table) |

Chosen direction: **C** (owner, 2026-10-15, after the cascade effects and the enterprise check below).

### 5.2 Enterprise check: later needs, added on top without redoing

| Later need | With C | With today's structure |
|---|---|---|
| a machine-readable test catalogue for an integrating product | a command printing every `info` | collected from nine places |
| a UI building a form from each test's parameters (types, limits) | JSON Schema from the Pydantic models | same, but the models are apart from the tests |
| third-party test packs installed separately (plugins) | only where the registry looks changes; the test is already self-contained | impossible: a plugin would have to edit `runtime.py` and `tests_config.py` |
| 50-100 tests | two files per test | nine places per test |
| a new identity field (e.g. OWASP reference, "since" version) | one field in `TestInfo`, with a default | nine places |

What would change the direction: tests becoming declarative files instead of Python (as Nuclei templates), a
different product; the tests' logic (oracles, request sequences, cross checks) does not fit such a format, and
`TestInfo` would still match an `info` block. Reverting is cheap: the change moves code, it does not rewrite test
logic or the report.

## 6. Design (to decide point by point)

### 6.1 One declaration per test - DECIDED (owner, 2026-10-15)

Fields: `id`, `name`, `priority`, `strategy`, `cwe`, `tags`, `depends_on`, `requires_pass`, `tool` (external tests);
the short names because `info.` already says whose they are. The results keep their field names (`test_id`,
`test_name`, `domain`, `cwe_id`, `tool_name`): report and JSON unchanged.

The identity of a test is one frozen Pydantic object, validated when the module is imported:

```python
class Test21RbacEnforcement(BaseTest[Test21Params]):
    info = TestInfo(
        id="2.1",
        name="Only Authorized Users Access Privileged Endpoints",
        priority=2,
        strategy=TestStrategy.GREY_BOX,
        cwe="CWE-285",
        tags=("authorization", "rbac", "OWASP-API5:2023"),
    )
```

`domain` is derived from the ID, not written; `depends_on`, `requires_pass`, `tags` default to empty. External tests
use the same object with `tool` set. The hand-written validator goes; a Pydantic error becomes the same
`TestDefinitionError` listing every problem, as today. Duplicate IDs and prerequisites naming no test stay checked
by the registries (they span several tests).

### 6.2 The parameters live with the test - DECIDED (owner, 2026-10-15)

Details decided: the model is named by the class declaration `BaseTest[Test21Params]` (mypy then knows the type
`self.params(target)` returns; an attribute `params_model = ...` would make every test repeat the type by hand,
unchecked); models are named `Test<D><N>Params` ("Config" is confused with `config.yaml` and `ToolConfig`); a test
without parameters declares none (`class Test03...(BaseTest)`, the empty `Test03Config` goes) and keys under it are
rejected ("test 0.3 has no parameters"); a test reads only its own parameters (no test reads another's today,
checked with grep).

The parameter model is written in the test's module, next to the code that uses it, and named by the class
declaration (`BaseTest[Test21Params]`; a test without parameters declares none). The test reads them with
`self.params(target)`, typed as its own model (mypy checks every parameter name), and sees only its own.

Consequences:

- `src/test_config/` (seven domain modules, the domain containers, `RuntimeTestsConfig`) and
  `src/config/schema/tests_config.py` go: there is nothing to copy, so nothing to forget.
- **Phase order (3.3.1):** the tests are discovered in Phase 1, right after the YAML is read (importing modules, no
  network), and `tests:` is validated against the models they declare. A wrong parameter still stops the run before
  any contact with the target (exit 10); a wrong test declaration now stops it before the specification download
  instead of after. `validate-config` already discovers the tests: no extra cost. An unknown test or parameter gives
  the same message as any unknown key, with the closest name.
- **7.2's check (3.3.2)** moves into 7.2's parameter model; it receives the resource names through Pydantic's
  validation context. Same messages, same moment; `ToolConfig` knows no test.
- **Dependency rule (3.3.4):** the `src.test_config` layer leaves the `lint-imports` contract, which becomes
  `core <- connectors <- tests | external_tests <- engine`; parameter models may use `core` helpers.
- The user's keys stay `tests.domain_<D>.test_<D>_<N>.<param>`, derived from the ID by one function (G5).
- `TargetContext` holds the parameters by test ID instead of one field per test.
- `scripts/check_config_keys.py` reads the tests' models for the `tests:` part (or that part is generated, 6.3).

Precondition: 6.6 (the Kong knowledge in 3.3 and 4.3, decided), since `core/gateway` can no longer import test parameters.

### 6.3 What is generated from the declarations - DECIDED (owner, 2026-10-16)

The parts that repeat the code are written into the files themselves, between markers (HTML comments in Markdown,
`#` comments in YAML), so the documentation stays plain Markdown complete on GitHub; `--check` in `dev:check` fails
when a part is out of date and shows the difference.

**Tool - DECIDED (owner, 2026-10-16): Cog** (`cogapp`, Ned Batchelder, MIT, 3.6.0 of 2025-09-21, Python 3.9-3.14),
a development dependency like ruff and mypy: it finds the markers, replaces their content (`-r`) and checks it
(`--check --diff`). The functions that build the tables are ours (`scripts/generate_docs.py`). Rejected: site
generators (MkDocs, Sphinx plugins: content only in a built site, the files on GitHub incomplete, no site today) and
a marker parser of our own (what Cog already does). Sources: https://cog.readthedocs.io/en/latest/running.html,
https://pypi.org/project/cogapp/.

Trial (scratch, 2026-10-16, cog 3.6.0): empty markers fail the check; generation writes only between the markers;
a priority changed in the code fails the check with the diff; a hand edit inside the markers fails it; a hand edit
outside passes; markers in YAML work and the YAML stays valid. Found: a stale `__pycache__` (edit of the same size
in the same second) hid a change; CI starts clean, the local command must run with an empty bytecode cache (to
verify when writing it).

Commands: `hatch run dev:gen` writes, `dev:check` runs `--check`.

**Catalogue "Needs" column - DECIDED (owner, 2026-10-16):** generated without it for now, with a link to "Test
portability" (`compatibility.md`), the measured and more complete copy of the same fact. The column comes back,
generated, when the tests declare what they need (6.4); the order of work changes, nothing is given up.

| Generated | From |
|---|---|
| the catalogue table in `docs/tests/README.md` | `info` of every test |
| the header table of every test page | `info` |
| the lists by strategy and by priority in `assessment-model.md` | `info` |
| the parameter tables in `configuration.md` | the parameter models (name, type, default, constraints, description) |
| the `tests:` section of `config.example.yaml` | the parameter models |

What stays written by hand: the prose of each test page (what it checks, how, why), the portability table (a
measurement on the labs), the roadmap. `dev:check` checks that every test has its page.

Side effect: a parameter's `description` becomes its only text, shown in the code, `configuration.md` and
`config.example.yaml`; the hand-written comments of `config.example.yaml` (e.g. "No default: empty = SKIP") move
into the descriptions.

**How much text - DECIDED (owner, 2026-10-16):** `config.example.yaml` gets the first sentence of each description
(the example stays short to read and copy), `configuration.md` the full description with its sources. Rule for test
authors, in the guide: the first sentence of a description must stand on its own.

### 6.4 What a test needs, declared

The "Needs" column, the startup warnings ("WHITE_BOX selected without a gateway") and the SKIP guards all describe
the same thing: what a test needs to run (user A's credentials, the admin account, the gateway, a parameter set). A
declaration (`needs=(Need.USER_A,)`) would generate the column and make the warnings exact per test. Whether the
engine also enforces it (SKIP before `execute`, instead of each test's guard) changes test behaviour: to decide. Can
be done after the rest.

Uses of the declaration (owner, 2026-10-16, "it may have other uses in the code"): startup warnings per test
instead of per strategy ("2.1 and 7.2 will SKIP: no user_a credentials", today `validate_cross_submodel_coherence`
reasons by strategy); one check by the engine before `execute`, with uniform SKIP messages, instead of each test's
guard; an integrator asking which tests can run with a configuration before running; the catalogue column.

### 6.5 One base for native and external tests - DECIDED (owner, 2026-10-16)

A common base in `src/core/` (importable by both `tests/` and `external_tests/`) holds `info`, `self.params()` and
the `_make_*` result helpers, written once; the two bases keep only what is theirs. Today `_metadata_kwargs` is
identical in both (its docstring in `external_tests/base.py` says "Mirrors BaseTest._metadata_kwargs() exactly");
the real differences are the transaction log (native) and the tool name (external). How a test is written does not
change; the report is identical.

The metadata and result plumbing (`_make_pass` ... `_make_error`) written once, shared by `BaseTest` and
`ExternalToolTest`; each keeps what is its own (HTTP client and transaction log; the tool, its connector and its
output).

### 6.6 The Kong knowledge in the parameters of 3.3 and 4.3 - DECIDED (owner, 2026-10-16)

All the Kong knowledge goes into the Kong adapter; six keys go (Breaking, CHANGELOG; none is set in the lab
configurations, all are in `config.example.yaml`): `test_3_3.plugin_names`, `field_clock_skew`, `field_algorithms`,
`field_validate_body`, `clock_skew_unconfigured_value`, `test_4_3.accepted_cb_plugin_names`.

- Plugin and field names become constants of `kong.py`, with the link to Kong's schema. A new plugin is added in the
  adapter, name and fields together.
- "0 means no limit" is APISIX's rule, not Kong's: the APISIX adapter translates `clock_skew: 0` into "no replay
  window" in the `SigningPolicy` concept, and 3.3 flags it without knowing the gateway.
- The engine passes no test parameter to the adapter; `core/gateway` imports no test.

Rejected: plugin names as gateway options (`gateway.kong.circuit_breaker_plugins`). A name alone is not enough: the
adapter must also know the plugin's fields (today `_BREAKER_THRESHOLD_FIELDS`, `_BREAKER_OPEN_FIELDS` in `kong.py`),
so a plugin with other fields would be found but not understood. It would also add a key and split the knowledge
between code and configuration. The APISIX adapter already keeps its plugin knowledge in code.

Facts (2026-10-16, from the gateways' source):

- Kong 3.9.0 `hmac-auth` schema: `clock_skew` number, default 300, `gt = 0` (0 is rejected); `algorithms` default
  `ALGORITHMS` = hmac-sha1, hmac-sha256, hmac-sha384, hmac-sha512; `validate_request_body` default false. The check
  rejects when `abs(time() - requestTime) > clock_skew`, with no special case for 0
  (https://github.com/Kong/kong/blob/3.9.0/kong/plugins/hmac-auth/schema.lua, `access.lua`). The current reference
  says hmac-sha1 is disabled by default (https://developer.konghq.com/plugins/hmac-auth/reference/): probably changed
  after 3.9.
- APISIX 3.13.0 `hmac-auth`: `clock_skew` integer, default 300, `minimum = 1`; the check is guarded by
  `if conf.clock_skew and conf.clock_skew > 0`, so 0 would skip it
  (https://github.com/apache/apisix/blob/3.13.0/apisix/plugins/hmac-auth.lua).

### 6.7 A command listing the tests - DECIDED (owner, 2026-10-16): with 6.4 or right after it

`apiguard list-tests` (and `--json` for programs) would print every test's `info` and parameter schema, as
`ruff rule --all`. Its main reader is the integrating product, whose first question is "with my configuration,
which tests run and which SKIP": the answer needs what each test needs (6.4). Done before 6.4, a first JSON format
without it would be read by integrators and then change; done with 6.4, it is complete from its first version.
Postponing costs nothing: with 6.1-6.3 the command only prints what the declarations already hold. Meanwhile the
generated catalogue lists the tests.

## 7. What changes, file by file

| Today | Lines | After |
|---|---|---|
| `src/test_config/domain_0.py` ... `domain_7.py` (7) | ~1,900 | each model, with its default constants and descriptions, **moves** into its test's module |
| domain containers `TestDomain<D>Config` | | gone: they only grouped |
| `src/test_config/runtime.py` | 150 | gone: it was the copy; parameters reach a test by its ID |
| `src/config/schema/tests_config.py` | 79 | replaced by one generic function validating `tests:` against the declared models |
| `metadata_problems` in `src/core/test_metadata.py` | ~90 | replaced by `TestInfo` (the file stays and holds it) |
| duplicated plumbing in `src/external_tests/base.py` | | the shared base (6.5) |

Changed: the 17 test modules (mechanical: `info`, parameter model, `self.params(target)`; no logic change); both
bases and both registries; `engine.py` (discovery in Phase 1, `tests:` validation, no 3.3/4.3 to the adapter);
`tool_config.py`; `config/schema/__init__.py`; `core/context.py`; `core/gateway/base.py` and `kong.py`;
`scripts/check_config_keys.py`; `pyproject.toml` (contract). New: `scripts/generate_docs.py`.

Documentation: generated parts (6.3); `add-a-native-test.md` and `add-an-external-test.md` rewritten; the files of
3.3.8 updated.

Who notices: users only the five keys of 6.6; integrators nothing (report and exit codes identical); authors of
their own tests adapt them (Breaking); a new test is a module and a page.

## 8. Steps (after the decisions)

Each step on its own: `dev:check`, three labs identical to their references.

1. **DONE (2026-10-16).** `TestInfo` and the shared base (6.1, 6.5): no configuration change. Approved (owner, 2026-10-16), with one more
   decision: a test module that fails to import **stops the startup** (`TestDefinitionError` naming the file and the
   error), native and external. Before, the registries logged a WARNING and ran without the test
   (`src/tests/registry.py`, `_import_module_safely`): a missing test reads as "nothing found", and with `TestInfo`
   validated at import an invalid declaration would have dropped the test silently.
   As built: `src/core/test_metadata.py` (`TestInfo`, `info_problems`), `src/core/assessment_test.py`
   (`AssessmentTest`: `info`, `_result`, `_make_*`), `src/core/test_discovery.py` (one discovery for both
   registries: import failures, test modules outside a package, missing or wrong-kind `info`, duplicate IDs);
   `BaseTest` and `ExternalToolTest` keep only their own parts; the 17 test modules and the external template
   converted. Verified: `dev:check`; nine declaration mistakes each stop the run with exit 10 and their message;
   three full runs (external tools included) identical to the C5 references, every declaration field of the
   report rows included. Found: nuclei's 240 s lab limit fires under machine load (Q-67).
   Verification of the next steps (owner, 2026-10-16): native runs on the three labs and external tests in
   `dev_mode` (old and new code on the same cached tool output; shown to catch a planted oracle mistake: PASS ->
   FAIL 13), one full live run at the end of the block, and a live run for any step touching the connectors.
2. The Kong knowledge out of 3.3 and 4.3 (6.6): precondition of step 3.
3. The parameters into the test modules (6.2): `src/test_config/` goes.
4. The generator (6.3).
5. `needs` (6.4) and the `list-tests` command (6.7), after the rest.
6. The trial of section 3 repeated: target, the module and the page.
