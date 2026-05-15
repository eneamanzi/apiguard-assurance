# Code-base Quality Checks — Pre-Release Sweep

## Context

Dopo le modifiche pesanti di questa sessione (rename `ext.X.Y` → `ext.X.Y.toolname`,
fix `artifact_label`, refactor 1.4 e 2.1 in helper methods, aggiornamenti docs),
serve una verifica sistematica che la codebase non abbia regressioni latenti su:

- Lint (Ruff)
- Type checking (mypy strict)
- Sicurezza (bandit)
- Dead code (vulture)
- Dipendenze vulnerabili (pip-audit)
- Hard rules architetturali da CLAUDE.md
- Consistenza test ↔ config ↔ runtime model

**Il tooling è già configurato** in `pyproject.toml` ma non c'è CI: nessuno ha mai
forzato `hatch run dev:check` come gate. Adesso lo facciamo manualmente.

---

## Piano stratificato

L'utente può approvare singoli tier o tutti. Ognuno è eseguibile in modo indipendente.

### Tier 1 — Static analysis suite (configurata, mai eseguita di recente)

Eseguire i comandi già definiti in `pyproject.toml [tool.hatch.envs.dev.scripts]`:

```bash
hatch run dev:lint    # ruff check . + mypy src/
hatch run dev:audit   # bandit -r src/ + vulture src/ --min-confidence 80
hatch run dev:deps    # pip-audit --desc on
```

**Atteso:** zero violazioni Ruff, zero errori mypy strict, zero finding bandit
HIGH/MEDIUM, vulture potrebbe segnalare codice morto da rimuovere, pip-audit
nessuna CVE attiva.

**Cosa fare con eventuali finding:**
- Ruff/mypy errors → fix puntuale (zero tolerance)
- Bandit HIGH → fix immediato. MEDIUM → valutare. LOW → triage.
- Vulture finding → rimuovere import/funzioni morte solo se davvero non usate
  (vulture ha falsi positivi su metodi pydantic/abstract).
- pip-audit CVE → aggiornare il package se possibile; documentare se rischio noto.

### Tier 2 — Hard rules grep verification (da CLAUDE.md)

Verifica meccanica via grep di ogni "Hard Rule — Non-Negotiable":

| Regola | Comando di verifica | Atteso |
|--------|---------------------|--------|
| No `pass`/`...`/`TODO`/`FIXME` | `grep -rn "^\s*pass$\|^\s*\.\.\.$\|TODO\|FIXME\|HACK" src/` | Solo legittimi in test/stub se ce ne sono |
| No `print()` | `grep -rn "print(" src/` | Solo strutturati (escludere structlog) |
| No bare `except` | `grep -rn "^\s*except:\|except Exception: pass" src/` | 0 |
| No magic numbers > 100 senza nome | Lettura manuale di costanti suspect | Tutti ge/le hanno costanti |
| No `SecurityClient` singleton | `grep -n "^_client\|SecurityClient()" src/` (escluso `engine.py`) | 0 |
| No numeri in nomi file modulo | `find src -name "*[0-9]*.py" \! -path "*/test_*" \! -path "*/domain_*"` | 0 |
| BaseTest non invoca subprocess | `grep -n "subprocess\|Popen\|run(" src/tests/` | 0 |
| English-only in src | Spot-check dei commenti recenti | English |
| `[REDACTED]` per credenziali | `grep -rn "password\|token" src/` filtrato | Solo redacted nei log |

### Tier 3 — Test class architecture compliance

Verifica che ogni `BaseTest` subclass abbia i **8 ClassVar obbligatori**
e ogni `ExternalToolTest` abbia anche `tool_name`:

```python
# Script di verifica (read-only) che ispeziona ogni classe via ast
required_native = {"test_id","test_name","domain","priority","strategy",
                   "depends_on","tags","cwe_id"}
required_external = required_native | {"tool_name"}
```

**File da ispezionare:** tutti i `src/tests/domain_*/test_*.py` e tutti i
`src/external_tests/ext_test_*.py`. Report con eventuali ClassVar mancanti.

### Tier 4 — Consistenza config ↔ test ↔ runtime model

Per ogni test che ha config (es. 1.4 → `Test14Config`):

- Esiste il blocco `tests.domain_N.test_N_N` in `config.yaml`?
- Esiste la Pydantic class in `src/config/schema/domain_N.py`?
- Esiste il `RuntimeTestNNConfig` in `src/core/models/runtime.py`?
- È popolato in `engine.py _phase_3_build_contexts()`?
- È usato nel test via `target.tests_config.test_N_N`?

Cinque punti che devono allinearsi. Una mancanza in uno qualsiasi → silent failure.

### Tier 5 — Dependency direction (architectural)

CLAUDE.md dichiara: `core/ ← connectors/ ← tests/ + external_tests/ ← engine.py`,
zero import laterali/upward/circolari.

Verifiche grep:
- `grep -rn "from src.engine\|from src.config.loader\|from src.discovery\|from src.report" src/tests/ src/external_tests/ src/connectors/ src/core/`
  → Atteso 0
- `grep -rn "from src.tests\|from src.external_tests" src/core/ src/connectors/`
  → Atteso 0
- `grep -rn "from src.connectors" src/core/`
  → Atteso 0

### Tier 6 — Cleanup operativo

- File artifact obsoleti in `outputs/tools/` (residui da prima del rename):
  - `ext_0_1_nuclei_nuclei_output.json`
  - `ext_1_5_sslyze_sslyze_output.json`
  - `ext_1_5_testssl_sh_output.json`
  - `ext_1_5_testssl_testssl_sh_output.json`
- Verificare che `outputs/crapi/` (un altro target) sia ancora rilevante o
  vada archiviato/rimosso.
- File `MILESTONE1_VALIDATION_AUDIT.md` da committare? Cancellare? Decidere.

---

## File chiave per la verifica

| File | Tipo di check |
|------|--------------|
| `pyproject.toml` | Scripts hatch dev |
| `CLAUDE.md` | Hard rules verbatim |
| Tutti `src/tests/domain_*/test_*.py` | ClassVar + architettura |
| Tutti `src/external_tests/ext_test_*.py` | ClassVar + architettura |
| `src/config/schema/domain_*.py` | Pydantic models per config |
| `src/core/models/runtime.py` | Runtime config models |
| `src/engine.py` | Popolamento runtime models |
| `config.yaml` | Blocchi config per ogni test |

---

## Verifica end-to-end

Dopo ogni fix, **un solo comando** garantisce non-regressione:

```bash
hatch run dev:check   # ruff + mypy + bandit + vulture
hatch run apiguard run --config config.yaml   # zero ERROR, stessi PASS/FAIL del baseline
```

Confronto rapido col baseline post-refactor (16:43 UTC, già salvato in
`/tmp/apiguard_refactor_baseline/`).

---

## Raccomandazione di ordine

1. **Tier 1** prima di tutto (potrebbe già rivelare problemi gravi)
2. **Tier 2** e **Tier 5** insieme (entrambi grep-based, rapidi)
3. **Tier 3** + **Tier 4** insieme (entrambi consistency checks)
4. **Tier 6** alla fine (cleanup)

Tempo stimato totale: 15-25 minuti se non emergono problemi reali. Più se ce ne sono.

---

## Tier aggiuntivi — standard pre-produzione

### Tier 7 — Secrets scan del repo (dogfooding)

Il progetto stesso implementa una secrets-detection (test 6.4). Ironico se il repo
contenesse credenziali. Verifica:

```bash
# Cerca pattern tipici in tutto il repo (escluso .git/__pycache__/outputs)
grep -rnE "(api[_-]?key|secret|password|token|bearer)[\"']?\s*[:=]\s*[\"'][^\"']{8,}" \
  --exclude-dir={.git,__pycache__,outputs,node_modules,tools} \
  /home/manzi/apiguard-assurance/
```

Verifica anche nella git history:
```bash
git log --all --full-history -p -- ".env" | head -100   # mai committato?
git log --all --full-history --diff-filter=D --summary | grep delete  # cosa è stato cancellato
```

Atteso: zero hit reali (i match dovrebbero essere solo placeholder nelle Pydantic descriptions
o nei comment, o `[REDACTED]`).

### Tier 8 — License audit delle dipendenze

```bash
hatch run pip install pip-licenses
hatch run pip-licenses --format=markdown
```

Verifica che ogni dipendenza abbia una licenza compatibile (MIT/BSD/Apache/etc.).
Bandiera rossa: GPL viral, AGPL, unknown. Per una tesi pubblica conta che siano
licenze permissive.

### Tier 9 — Build reproducibility & cold install

```bash
hatch build  # genera wheel + sdist in dist/
# Crea ambiente pulito da zero
python3 -m venv /tmp/cold-test
source /tmp/cold-test/bin/activate
pip install dist/apiguard_assurance-*.whl
apiguard --help  # comando funziona da fresh install?
```

Verifica che il packaging non si rompa e che un utente che fa `pip install` ottenga
un tool funzionante senza dover clonare il repo.

### Tier 10 — Teardown / resource cleanup verification

Dopo un run, verificare che Phase 6 abbia pulito tutto sul target:

```bash
# Sul target Forgejo: nessun repo/token residuo creato dai test
curl -u thesis-admin:Admin1234! "http://localhost:3000/api/v1/users/thesis-admin/tokens" | \
  jq '.[] | select(.name | contains("apiguard"))'
curl -u user-a:UserA1234! "http://localhost:3000/api/v1/repos/search?owner=user-a" | \
  jq '.data[] | select(.name | contains("apiguard"))'
```

Atteso: nessun token o repo residuo con prefix `apiguard-`. Se ce n'è, il teardown
non funziona e va investigato.

### Tier 11 — Documentation completeness

Ogni classe e funzione **pubblica** in `src/` deve avere una docstring (regola CLAUDE.md).
Verifica:

```bash
# Find public functions/classes without docstrings (rude approximation)
# Python ast-based script più affidabile di grep
```

Più granulare via Python:
```python
import ast
for path in glob('src/**/*.py'):
    tree = ast.parse(open(path).read())
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if not node.name.startswith('_') and not ast.get_docstring(node):
                print(f'{path}:{node.lineno}: missing docstring on {node.name}')
```

### Tier 12 — Reproducibilità della run

Per una tesi: il run deve essere riproducibile da chiunque legga.

- Versione di apiguard pinnata: leggere `[project] version` da pyproject.toml
- Versioni dei tool esterni pinnate: `expected_version` per nuclei/testssl/sslyze
  in `external_tools` di config.yaml
- Versione dei template nuclei pinnata: `tools/nuclei-templates` checkout SHA
- `CHANGELOG.md` / release notes presenti?
- Tag git per la milestone?

Verifica:
```bash
git tag -l                                # esistono tag?
cat pyproject.toml | grep "^version"      # versione esplicita?
grep -A1 "expected_version" config.yaml   # tool version pinning?
ls CHANGELOG.md 2>/dev/null || echo "MISSING"
```

### Tier 13 — Tesi-specific: architectural claims verification

`docs/apiguard_property.md` elenca 35+ proprietà architetturali con "Tipo di evidenza:
Empirica — dimostrata da X". Verificare per ogni P** che il riferimento sia ancora valido:

- Se cita `ext.0.1` → deve esistere come `ext.0.1.nuclei`
- Se cita `_relativize_display_path` → grep deve trovarlo in `connectors/base.py`
- Se cita "test 6.2 e 6.4 usano response_inspector" → verifica gli import

L'abbiamo già fatto in parte (rename dei test_id), ma una passata di verifica meccanica
chiude il loop.

---

## Cosa NON è incluso (volutamente)

- **Unit test pytest**: il progetto non li ha (per design, e2e only contro target reale per CLAUDE.md)
- **Coverage**: senza unit test non ha senso
- **CI setup (.github/workflows)**: fuori scope per questa milestone (potrebbe essere
  un follow-up: trasformare `hatch run dev:check` in un workflow GitHub Actions)
- **Pre-commit hooks**: idem
- **Performance profiling / load testing**: non rilevante per una tesi
- **SBOM / SPDX manifesto**: overkill per una tesi (ma standard per software regolato)
- **Penetration test del tool stesso**: il tool non è esposto come servizio, gira locale
- **Localization / i18n**: tutto English-only by design (CLAUDE.md)
