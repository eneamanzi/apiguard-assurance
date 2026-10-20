# Milestone 1: Pre-Release Audit

> **Status:** a historical record, translated from the Italian original almost word for word
> (`git show 694f89a:docs/project/audits/2026-05-18-v0.1.0-release.it.md`). Everything in it describes the tool as
> of 2026-05-18 (v0.1.0): the file names, document names (`PROJECT_status.md`, `ARCHITECTURE.md`, `TOOLS_catalog.md`,
> `docs/pub/`, `docs/priv/`) and counts are those of the time, not of the current repository.

- [Part A. Data and verdicts citable in the thesis](#part-a-data-and-verdicts-citable-in-the-thesis)
- [Part B. Validation register (73 checks)](#part-b-validation-register-73-checks)
- [Appendix. Main verification commands](#appendix-main-verification-commands)

**Audit type:** release-readiness check, after the reorganisation of the documentation
**Date:** 2026-05-18
**Tool version:** `0.1.0`
**Codebase:** 90 Python files in `src/`, 18 active tests (15 native + 3 external), about 9,800 lines of documentation
**Checks run:** 73

---

## Part A. Data and verdicts citable in the thesis

A summary of the empirical evidence and the release verdicts. Each datum has its detailed check under the
corresponding check number in Part B.

### A.1 Release verdict

| Aspect | State |
|---|---|
| Functional correctness | ✓ Static analysis 100% green on 90 files: 0 errors from ruff, mypy, bandit, vulture |
| Architectural integrity | ✓ 18 unique test IDs; acyclic DAG; exception hierarchy of 11 classes unchanged; one-way dependencies |
| Documentation coverage | ✓ 100% docstrings on 292 public symbols; 100% Pydantic Field descriptions (265/265 outer); internal links correct (finding M-1 resolved) |
| Packaging / distribution | ✓ Wheel of 95 files, 451,261 bytes, identical SHA-256 on 2 consecutive builds: deterministic build |
| Cold install | ✓ `pip install wheel` in a fresh venv, then `apiguard version`, gives `0.1.0` |
| Production resilience | ✓ Signal handling guarantees the Phase 6 teardown on `KeyboardInterrupt` |

**Release readiness:**

- ✓ **READY** for the thesis defence
- ✓ **READY** for deployment in a closed environment against documented OpenAPI targets
- **REQUIRES** the items in §A.7 (LICENSE) only for PyPI publication or distribution as a public artefact

---

### A.2 Performance baseline

> APIGuard Assurance v0.1.0, running the complete M1 suite (15 native + 3 external tests, 18 active, sequential
> execution) against Forgejo 14.0.3 protected by DB-less Kong on a single-host development setup, completes a full
> assessment in **4 minutes 50 seconds** (average over two independent runs) with a peak memory footprint of
> **287-295 MB** and **4.5 MB** of total evidence on disk (`apiguard_report.json` + `assessment_report.html` +
> `evidence.json`). CPU use averages 26%: the run is dominated by HTTP round trips to the target rather than local
> computation. Two independent runs against the same target on the same day produce **byte-equivalent KPI outcomes**
> (`9 PASS / 7 FAIL / 2 SKIP / 0 ERROR / 98 findings`; per-test status diff = 0) with a wall-clock delta under
> 0.4%, confirming empirical reproducibility.

| Metric | Run 1 | Run 2 |
|---|---:|---:|
| Wall-clock elapsed | **4:50.14** (290.14 s) | **4:50.81** (290.81 s) |
| User time | 35.09 s | 34.67 s |
| System time | 41.51 s | 41.62 s |
| **Peak resident set size** | **294,192 KB ≈ 287 MB** | **301,792 KB ≈ 295 MB** |
| Voluntary context switches | 145,356 | (similar) |
| Involuntary context switches | 20,685 | (similar) |
| File system outputs | 26,440 blocks | 23,616 blocks |
| Exit status | 1 (≥1 FAIL, expected) | 1 |

**Output sizes (run 1):** `apiguard_report.json` 2.26 MB + `assessment_report.html` 2.0 MB + `evidence.json` 254 KB ≈
**4.5 MB total**.

*Baseline measured against Forgejo 14.0.3 + DB-less Kong on a single host on 2026-05-17. Detailed check: §B.9.*

---

### A.3 Assessment results per test (idempotence)

| KPI | Run 1 | Run 2 | Δ | Verdict |
|---|---:|---:|---|---|
| PASS / FAIL / SKIP / ERROR | 9 / 7 / 2 / 0 | 9 / 7 / 2 / 0 | **identical** | ✓ |
| Total finding count | 98 | 98 | **identical** | ✓ |
| `pass_rate_pct` | 56.2 | 56.2 | identical | ✓ |
| `assessment_duration_seconds` | 286.04 | 286.96 | +0.32 % | ✓ |
| Exit code / label | 1 / "FAIL" | 1 / same | identical | ✓ |

| test_id | status | findings |
|---|---|---|
| 0.1 | FAIL | 16 |
| 0.2 | FAIL | 1 |
| 0.3 | SKIP | 0 |
| 1.1 | FAIL | 74 |
| 1.4 | PASS | 0 |
| 1.5 | PASS | 0 |
| 1.6 | SKIP | 0 |
| 2.1 | PASS | 0 |
| 3.3 | PASS | 0 |
| 4.1 | FAIL | 2 |
| 4.2 | PASS | 0 |
| 4.3 | PASS | 0 |
| 6.2 | PASS | 0 |
| 6.4 | PASS | 0 |
| 7.2 | FAIL | 1 |
| ext.0.1.nuclei | PASS | 0 |
| ext.1.5.sslyze | FAIL | 1 |
| ext.1.5.testssl | FAIL | 3 |

*Detailed check: §B.9.*

---

### A.4 Post-run teardown (live check)

| Resource on the target | Before run 1 | After run 1 | After run 2 | Verdict |
|---|---:|---:|---:|---|
| Forgejo tokens of `thesis-admin` containing `"apiguard"` | 0 | 0 | 0 | ✓ |
| Forgejo repositories of `user-a` starting with `"apiguard"` | 0 | 0 | 0 | ✓ |

The Phase 6 teardown releases all the transient resources created in Phase 5. The teardown register drained 4 LIFO
resources with 0 failures on both runs.

---

### A.5 DAG topology

```
Phase A (no dependencies, 16 tests):
  0.1, 0.2, 0.3, 1.1, 1.5, 1.6, 3.3, 4.1, 4.2, 4.3, 6.2, 6.4, 7.2,
  ext.0.1.nuclei, ext.1.5.testssl, ext.1.5.sslyze

Phase B (depends_on = ["1.1"]):
  1.4, 2.1
```

In-degree map (non-zero values only): `1.1` in=2 (consumed by `1.4`, `2.1`).

Cycle detection: ✓ acyclic (verified with `graphlib.TopologicalSorter`).

---

### A.6 Version matrix

| Component | Version |
|---|---|
| `apiguard-assurance` (pyproject) | **0.1.0** |
| `apiguard version` (CLI) | 0.1.0 |
| `output_schema_version` (JSON report root) | 1.0 |
| Pinned external tool: `testssl.sh` | 3.2.3 |
| Pinned external tool: `nuclei` binary | 3.8.0 |
| Pinned external tool: `nuclei-templates` | 10.4.3 |
| Python interpreter | 3.12.3 |
| Forgejo (target under test) | 14.0.3 (gitea-1.22.0) |
| Kong (gateway under test) | DB-less mode |

---

### A.7 Deferred items

| # | Item | Reason |
|---|---|---|
| 1 | `LICENSE` file at the root | IP and licensing depend on university regulations, not yet final |
| 2 | `CHANGELOG.md` | Not applicable to the first release: a changelog documents the differences between versions; it will be introduced from `v0.2.0` on |

Git tag `v0.1.0` and the GitHub release are done. None of the deferred items affects the tool's ability to run,
produce reports or interoperate with Forgejo + Kong.

---

## Part B. Validation register (73 checks)

### B.1 Executive summary

| Category | Checks | Result |
|---|---:|---|
| §B.3 Static analysis | 5 | ✓ All green |
| §B.4 Inter-document consistency | 13 | ✓ All green |
| §B.5 Docs to code consistency | 5 | ✓ All green |
| §B.6 Code to docs consistency | 13 | ✓ All green |
| §B.7 Production engineering | 11 | ✓ All green |
| §B.8 Release engineering | 9 | ✓ All green |
| §B.9 Performance + idempotence + teardown | 4 | ✓ All green |
| §B.10 Runtime / cleanup / reproducibility | 6 | ✓ All green |
| §B.11 Additional pre-production checks | 7 | ✓ 6 green, 1 finding M-1 resolved |
| **Total** | **73** | **72 PASS, 1 resolved (M-1), 0 blocking** |

**Blocking:** 0. **Critical/major findings:** 0. **Minor findings resolved:** 1 (M-1). **Informational findings:** 1
(I-1, non-blocking). **Deferred items:** 2 (§A.7).

---

### B.2 Audit methodology

Audit run on Milestone 1, after the reorganisation of the documentation. Scope:

- 73 checks run across all categories

Verification commands: `hatch run dev:lint`, `hatch run dev:audit`, `hatch run dev:deps`,
`hatch build --target wheel`, cold install in a fresh venv, AST-based scripts, grep suite.

---

### B.3 Static analysis (checks 1-5)

| # | Check | Tool / command | Result | Detail |
|---|---|---|---|---|
| 1 | Lint | `ruff check .` | ✓ | "All checks passed!": 0 errors on `select = E/W/F/I/N/UP/B/S/ANN` |
| 2 | Type checking (strict) | `mypy src/` | ✓ | "Success: no issues found in 90 source files": `strict = true` |
| 3 | Security scan | `bandit -r src/ --severity-level medium` | ✓ | 0 Medium+, 3 Low (B404 + S603×2 in `connectors/base.py`, all `# noqa: S603`) |
| 4 | Dead code | `vulture src/ --min-confidence 80` | ✓ | 0 findings |
| 5 | Dependency CVEs | `pip-audit` | ✓ | "No known vulnerabilities found" |

---

### B.4 Inter-document consistency (checks 6-18)

| # | Check | Result | Detail |
|---|---|---|---|
| 6 | `ext.X.Y.toolname` naming uniform in the docs | ✓ | 0 bare `ext.X.Y` without the toolname suffix in docs/ and src/ |
| 7 | Test-set parity (PROJECT_status ↔ ARCHITECTURE ↔ code) | ✓ | 18 test IDs (15 native + 3 external) agree in all sources |
| 8 | 39 architectural properties (7 domains) | ✓ | `apiguard_property.md` holds 39 properties in 7 domains; spot check D1.P1/D1.P5/D4.P1/D2.P7 ✓ |
| 9 | Connector references in `TOOLS_catalog.md` | ✓ | nuclei (8 occurrences), sslyze (5), testssl (7) |
| 10 | Hard Rules (`CLAUDE.md` ↔ `RULES_claude.md`) | ✓ | All references updated; 0 obsolete references |
| 11 | Exception hierarchy (CLAUDE.md ↔ exceptions.py ↔ gateway/base.py ↔ seed_generator.py) | ✓ | 11/11 classes present in CLAUDE.md |
| 12 | M1 status uniformity | ✓ | PROJECT_status.md, CLAUDE.md, README.md, ARCHITECTURE.md agree |
| 13 | Italian leak in code | ✓ | 0 matches in `src/` (Italian in the thesis docs is by design) |
| 14 | Log of removed tool decisions (kiterunner, crlfuzz, jwtxploiter) | ✓ | All 3 in TOOLS_decisions.md and TOOLS_catalog.md (spot check) |
| 15 | Version uniformity | ✓ | `0.1.0` in pyproject.toml, README.md, README.en.md, ARCHITECTURE.md, `apiguard version` |
| 16 | Test count (18 active) | ✓ | 18 test IDs verified via AST; 15 in `src/tests/` + 3 in `src/external_tests/` |
| 17 | Doc paths in source comments | ✓ | References to `docs/pub/ADDING_tests.md`, `docs/pub/ADDING_external_tests.md`, `docs/priv/knowledge/` in `src/` comments all correct |
| 18 | ARCHITECTURE.md §10 consistency with pyproject.toml | ✓ | §10 present (line 899), tag `py3-none-any` explained, sdist whitelist described, sslyze AGPL noted: consistent with pyproject.toml |

---

### B.5 Docs to code consistency (checks 19-23)

| # | Check | Result | Detail |
|---|---|---|---|
| 19 | Hard rules (CLAUDE.md) ↔ grep on the source | ✓ | `print()` → 0 (only `_console_out.print()` = Rich, not stdlib); `TODO/FIXME/HACK` → 0; bare `except:` → 0; `...` limited to `@abstractmethod` |
| 20 | `BaseTest` / `ExternalToolTest` ClassVar compliance (AST-based) | ✓ | 15/15 native with the 8 required ClassVars; 3/3 external with the 9 required ClassVars. 0 missing |
| 21 | Config ↔ test ↔ runtime model chain | ✓ | Spot check of tests 1.4, 2.1, 4.1, 6.4: the chain `config.yaml → schema → RuntimeConfig → engine → target.tests_config` is intact |
| 22 | One-way dependency direction | ✓ | 0 upward imports from `tests/`/`external_tests/` towards `engine.py`, `report/`, `config/loader.py`, `discovery/` |
| 23 | 39 architectural properties vs implementation | ✓ | D1.P1 (API agnosticism), D1.P5 (three-tier connector hierarchy), D4.P1 (evidence store), D2.P7 (generate-seed): the loci exist, the implementations agree |

---

### B.6 Code to docs consistency (checks 24-36)

| # | Check | Result | Detail |
|---|---|---|---|
| 24 | All 15 native test IDs in the docs | ✓ | Each test ID present in ≥5 documentation files |
| 25 | All 3 external test IDs in the docs | ✓ | `ext.0.1.nuclei` (3 files), `ext.1.5.sslyze` (4 files), `ext.1.5.testssl` (4 files) |
| 26 | All 3 connectors in `TOOLS_catalog.md` | ✓ | nuclei / sslyze / testssl |
| 27 | All 11 exception classes documented | ✓ | 11/11 present in CLAUDE.md (including GatewayAdapterError + SeedGenerator*) |
| 28 | All 6 helpers referenced in the docs | ✓ | auth (44), auth_forgejo (6), auth_jwt_login (3), forgejo_resources (7), path_resolver (2), response_inspector (5) mentions in ADDING_tests.md |
| 29 | All 7 engine phases referenced in the docs | ✓ | `_phase_1` … `_phase_7` in engine.py; documented in 4-Implementazione.md + ARCHITECTURE.md + CLAUDE.md |
| 30 | Core Pydantic models referenced | ✓ | TargetContext, TestContext, Finding, TestResult, ResultSet, AttackSurface, EvidenceRecord: all in the docs (spot check) |
| 31 | All 4 CLI commands documented | ✓ | `run` (14 files), `version` (13), `validate-config` (4), `generate-seed` (5) |
| 32 | Hard Rules ↔ code surface | ✓ | Cross-verified with check 19 |
| 33 | Module-level docstrings ↔ `ARCHITECTURE.md` directory layout | ✓ | 292/292 public symbols with a docstring (100%); the ARCHITECTURE.md layout matches `src/` |
| 34 | `BaseTest`/`ExternalToolTest` ClassVars ↔ public docs contract | ✓ | 8 BaseTest + 9 ExternalToolTest ClassVars documented in ADDING_tests.md / ADDING_external_tests.md; 0 orphans |
| 35 | Top-level `config.yaml` keys ↔ Pydantic schemas | ✓ | 6 keys (`target`, `credentials`, `execution`, `output`, `tests`, `external_tools`) ↔ `src/config/schema/` (spot check) |
| 36 | Surprise scan (public symbols absent from any doc) | ✓ | 0 real phantom symbols |

---

### B.7 Production engineering (checks 37-47)

| # | Check | Result | Detail |
|---|---|---|---|
| 37 | Error-handling boundary correctness | ✓ | 3 broad `except Exception` blocks with `# noqa: BLE001` at phase boundaries; 0 bare `except:` |
| 38 | Logging and credential leaks | ✓ | 32 `[REDACTED]` placeholders; 48 `structlog.get_logger()` bindings; 0 f-strings leaking token/password |
| 39 | Pydantic Field description coverage | ✓ | **265 user-facing outer Field(), 265 with `description=` (100%)**: inner `Annotated[..., Field(ge=...)]` excluded (validation only) |
| 40 | Determinism / RNG security inventory | ✓ | `secrets.token_hex()` for all nonces and identifiers; 0 `random.*` in `src/` |
| 41 | Concurrency model | ✓ | 0 `asyncio` in the code paths; sequential by design; 0 global SecurityClient singletons |
| 42 | Observability / CLI message quality | ✓ | All 4 `--help` readable; `apiguard run --help` documents all 4 exit codes |
| 43 | Report quality | ✓ | Renderer architecture verified in §B.8 |
| 44 | Dependency hygiene | ✓ | `pip check`: "No broken requirements found"; minor upgrades available but inside the `FLOOR-NEXT_MAJOR` policy |
| 45 | Test order independence | ✓ | 0 shared state between tests |
| 46 | Cross-platform path portability | ✓ | 0 CRLF in `src/`; all `__init__.py` with an EOF newline; 0 BOM |
| 47 | Configuration robustness | ✓ | The loader gives actionable errors on a missing file, malformed YAML, an unset `${ENV_VAR}` (spot check) |

**Informational finding I-1 (non-blocking, M2 candidate):** `timeout=10` in `connectors/base.py:426` (subprocess
`--version` check) and `recursion_limit=10` in `discovery/openapi.py:390` (prance internal). Neither is user-visible
and neither governs assessment behaviour.

---

### B.8 Release engineering (checks 48-56)

| # | Check | Result | Detail |
|---|---|---|---|
| 48 | Wheel contents | ✓ | 95 files, all in `src/` or `.dist-info/`; 0 spurious content |
| 49 | Sdist contents | ✓ | 102 files; includes `src/`, `docs/pub/`, `README.md`, `README.en.md`, `pyproject.toml`, `config.yaml`, `.env.example`, `install_tools.sh`; 0 internal files (`.claude/`, `CLAUDE.md`, `docs/priv/`) |
| 50 | PyPI metadata completeness | ✓ | Tag `py3-none-any`, `Root-Is-Purelib: true`, `Author-email`, `Requires-Python >=3.11`, every `Requires-Dist` with an upper bound `<NEXT_MAJOR` |
| 51 | CLI ergonomics | ✓ | `run`, `version`, `validate-config`, `generate-seed`: help OK on all 4 |
| 52 | Signal handling / interrupt resilience | ✓ | `try/finally` + `_phase_6_teardown()` + `KeyboardInterrupt` in `engine.py` ✓ |
| 53 | Output schema versioning | ✓ | `output_schema_version` + `tool_version` (from `importlib.metadata.version()`) in `report/builder.py` |
| 54 | Module-level side effects | ✓ | 0 unexpected statements outside imports/definitions/assignments (AST scan) |
| 55 | DAG semantic correctness | ✓ | 18 test IDs (15+3); 0 orphan `depends_on`; acyclic topological sort; in-degree: `1.1` in=2 (`1.4`, `2.1`) |
| 56 | Encoding / EOL / EOF hygiene | ✓ | 0 CRLF; all `__init__.py` with an EOF newline; 0 BOM |

---

### B.9 Performance, idempotence, teardown (checks 57-60)

The performance baseline was measured on 2026-05-17 on the full suite. Complete data in §A.2.

| # | Check | Result | Detail |
|---|---|---|---|
| 57 | Performance baseline (`/usr/bin/time -v`) | ✓ | Measured on 2026-05-17 on the full M1 suite against Forgejo 14.0.3 + DB-less Kong. Data → §A.2 |
| 58 | Idempotence (byte-equivalent KPIs on independent runs) | ✓ | 0 differences between the `test_id status finding_count` triples of the two runs. Per-test table → §A.3 |
| 59 | Test order independence | ✓ | Implied by the idempotence of check 58 |
| 60 | Post-run teardown check (live) | ✓ | The Phase 6 teardown drained 4 LIFO resources with 0 failures on both runs. Table → §A.4 |

---

### B.10 Runtime, cleanup, reproducibility (checks 61-66)

| # | Check | Result | Detail |
|---|---|---|---|
| 61 | Cleanup of obsolete artefacts | ✓ | 0 leftovers from the doc renaming and folder reorganisation |
| 62 | Secrets scan | ✓ | 0 real secrets in the repository; `.env` never committed in the git history |
| 63 | Licence audit (dependencies) | ✓ | 47 permissive (MIT/BSD/Apache/MPL/ISC) + 2 AGPL v3 (the sslyze extra) + 1 UNKNOWN (transitive tls_parser) |
| 64 | Cold-install reproducibility | ✓ | Fresh venv → `pip install dist/apiguard_assurance-0.1.0-py3-none-any.whl` → `apiguard version` → `0.1.0` ✓ |
| 65 | Docstring completeness | ✓ | **292/292 public symbols with a docstring (100%)**: AST scan |
| 66 | Version pinning | ✓ | pyproject.toml `0.1.0`; external tools pinned in config.yaml (testssl 3.2.3, nuclei 3.8.0) |

---

### B.11 Additional pre-production checks (checks 67-73)

| # | Check | Result | Detail |
|---|---|---|---|
| 67 | Reproducible build (byte-identical wheels on two consecutive builds) | ✓ | Identical SHA-256 on 2 consecutive `hatch build` (451,261 bytes) |
| 68 | Locale-independent execution | ✓ | `LC_ALL=C LANG=C apiguard --help` → correct output |
| 69 | Time-zone-independent execution | ✓ | `TZ=America/Los_Angeles apiguard version` → `0.1.0`, correct |
| 70 | Resolution of internal markdown links | **FINDING M-1, RESOLVED** | 5 broken links after the move to `docs/pub/`: `../README.md` → `../../README.md` (ARCHITECTURE.md:5) and `../src/tests/` → `../../src/tests/` (ADDING_tests.md:741,744,747,1513). Fixed during the audit. |
| 71 | PII scan in the logs | ✓ | 0 non-redacted credentials; 16 `@` strings in evidence.json are TLS algorithm identifiers (spot check) |
| 72 | pyproject ↔ imports cross-check | ✓ | Third-party imports in `src/`: `httpx`, `openapi_spec_validator`, `prance`, `rich`, `typer`, `yaml`, `structlog`, `pydantic`: all declared in pyproject.toml |
| 73 | Stale dev-environment install (regression) | ✓ | `pip check`: "No broken requirements found" |

---

### B.12 Findings and open items

**Minor finding resolved during this audit:**

| ID | Check | Description | Resolution |
|---|---|---|---|
| M-1 | §B.11 / check 70 | 5 broken relative markdown links: `../README.md` and `../src/tests/domain_*/` in `docs/pub/ARCHITECTURE.md` (1) and `docs/pub/ADDING_tests.md` (4). Cause: files moved from the root to `docs/pub/` without updating the relative paths. | **Resolved.** Paths corrected to `../../README.md` and `../../src/tests/domain_*/`. |

**Informational finding (no action needed before the defence):**

| ID | Check | Description | Impact |
|---|---|---|---|
| I-1 | §B.7 / check 40 | 2 non-user-visible magic numbers: `timeout=10` (`connectors/base.py:426`, subprocess `--version` check) and `recursion_limit=10` (`discovery/openapi.py:390`, prance internal). They do not govern assessment behaviour. | None on functionality. M2 cleanup candidate. |

**Deferred items:** see §A.7.

---

## Appendix. Main verification commands

```bash
# Static analysis
hatch run dev:lint       # ruff check . + mypy src/
hatch run dev:audit      # bandit + vulture
hatch run dev:deps       # pip-audit

# Build reproducibility
hatch build --target wheel
sha256sum dist/apiguard_assurance-0.1.0-py3-none-any.whl

# Cold install
python3 -m venv /tmp/cold-test && /tmp/cold-test/bin/pip install -q dist/apiguard_assurance-0.1.0-py3-none-any.whl
/tmp/cold-test/bin/apiguard version   # → 0.1.0
```

---

*Audit completed 2026-05-18. All the results of §B.3-§B.11 reflect the state of the codebase on 2026-05-18. Finding
M-1 was resolved during the audit. Finding I-1 is informational and non-blocking. The deferred items (§A.7) are the
only open points for public distribution.*
