# Setup Completo: Infrastruttura Target + Scaffolding Tool Python

---

## PARTE 1 — Smantellamento e Ricostruzione dell'Ambiente Target

### 1.1 — Bonifica dell'ambiente esistente

Questi comandi spengono lo stack attivo, rimuovono container, volumi e reti orfane senza toccare il demone Docker né le immagini già scaricate (che verranno riutilizzate).

```bash
# Stop e rimozione forzata di tutti i container in esecuzione
# relativi al progetto (pattern sul nome)
docker compose -f ~/apiguard-assurance/docker-compose.yml down --volumes --remove-orphans 2>/dev/null || true

# Pulizia difensiva: rimuovi container con nomi noti anche se
# il compose file non fosse raggiungibile
docker rm -f forgejo forgejo-db kong 2>/dev/null || true

# Rimuovi le reti orfane create da compose precedenti
docker network prune -f

# Verifica che le porte siano liberate
ss -tlnp | grep -E '3000|8000|8001'
# Output atteso: nessuna riga. Se compaiono righe, il processo
# che occupa la porta non e' stato terminato correttamente.

# Rimuovi la directory del progetto precedente
rm -rf ~/apiguard-assurance
```

---

### 1.2 — Creazione della struttura delle directory

```bash
mkdir -p ~/apiguard-assurance/kong
cd ~/apiguard-assurance
```

---

### 1.3 — Configurazione Kong DB-less (`kong/kong.yml`)

Il file dichiara un solo service che punta al container Forgejo sulla rete Docker interna, con una route che intercetta tutto il prefisso `/api`. Il flag `strip_path: false` preserva il path originale nel forwarding verso il backend: se fosse `true`, Kong rimuoverebbe il prefisso `/api` prima di passare la request a Forgejo, rompendo il routing interno dell'applicazione.

```bash
cat > ~/apiguard-assurance/kong/kong.yml << 'EOF'
_format_version: "3.0"

services:
  - name: forgejo-service
    url: http://forgejo:3000
    connect_timeout: 5000
    read_timeout: 30000
    write_timeout: 30000
    routes:
      - name: forgejo-api-route
        paths:
          - /api
        strip_path: false
        preserve_host: false
EOF
```

I timeout (`connect_timeout`, `read_timeout`, `write_timeout`) sono espressi in millisecondi e corrispondono ai valori di riferimento della Garanzia 4.2 (`connect_timeout <= 5s`, `read_timeout <= 30s`). Averli nel `kong.yml` rende immediatamente verificabile il test White Box di quel dominio senza Admin API.

---

### 1.4 — `docker-compose.yml`

Rispetto alla baseline, ho aggiunto:
- `FORGEJO__security__SECRET_KEY` con un valore fisso per rendere l'ambiente riproducibile tra restart (senza questo, Forgejo rigenera la chiave a ogni boot e invalida le sessioni attive).
- `FORGEJO__api__ENABLE_SWAGGER=true` che forza l'esposizione dell'endpoint `/api/swagger` necessario per il discovery OpenAPI del tool.
- `FORGEJO__log__LEVEL=Info` per evitare log verbosi in modalità debug che potrebbero saturare il buffer di stdout.
- I commenti inline per tracciabilità accademica.

```bash
cat > ~/apiguard-assurance/docker-compose.yml << 'EOF'
version: "3.8"

networks:
  lab-net:
    driver: bridge

volumes:
  forgejo-data:
  forgejo-db-data:

services:

  # PostgreSQL 15: backend di persistenza per Forgejo.
  # Versione Alpine per footprint ridotto in ambiente di laboratorio.
  forgejo-db:
    image: postgres:15-alpine
    container_name: forgejo-db
    restart: unless-stopped
    environment:
      - POSTGRES_USER=forgejo
      - POSTGRES_PASSWORD=forgejopassword
      - POSTGRES_DB=forgejo
    volumes:
      - forgejo-db-data:/var/lib/postgresql/data
    networks:
      - lab-net
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U forgejo"]
      interval: 10s
      timeout: 5s
      retries: 5

  # Forgejo 14: API REST target dell'assessment.
  # INSTALL_LOCK=true bypassa il wizard di primo avvio.
  # ENABLE_SWAGGER=true espone /api/swagger per OpenAPI discovery.
  forgejo:
    image: codeberg.org/forgejo/forgejo:14
    container_name: forgejo
    restart: unless-stopped
    environment:
      - USER_UID=1000
      - USER_GID=1000
      - FORGEJO__database__DB_TYPE=postgres
      - FORGEJO__database__HOST=forgejo-db:5432
      - FORGEJO__database__NAME=forgejo
      - FORGEJO__database__USER=forgejo
      - FORGEJO__database__PASSWD=forgejopassword
      - FORGEJO__server__HTTP_PORT=3000
      - FORGEJO__server__ROOT_URL=http://localhost:3000/
      - FORGEJO__security__INSTALL_LOCK=true
      - FORGEJO__security__SECRET_KEY=a8f3b2c1d7e4f9a2b5c8d1e6f3a9b2c5
      - FORGEJO__api__ENABLE_SWAGGER=true
      - FORGEJO__log__LEVEL=Info
    volumes:
      - forgejo-data:/data
      - /etc/localtime:/etc/localtime:ro
    networks:
      - lab-net
    ports:
      - "3000:3000"
    depends_on:
      forgejo-db:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3000/api/healthz"]
      interval: 15s
      timeout: 10s
      retries: 5

  # Kong 3.9 in modalita' DB-less.
  # La configurazione dichiarativa e' in ./kong/kong.yml.
  # Admin API esposta su 8001 per i test White Box (Dominio 4/6).
  kong:
    image: kong:3.9
    container_name: kong
    restart: unless-stopped
    environment:
      - KONG_DATABASE=off
      - KONG_DECLARATIVE_CONFIG=/kong/kong.yml
      - KONG_PROXY_LISTEN=0.0.0.0:8000
      - KONG_ADMIN_LISTEN=0.0.0.0:8001
      - KONG_PROXY_ACCESS_LOG=/dev/stdout
      - KONG_ADMIN_ACCESS_LOG=/dev/stdout
      - KONG_PROXY_ERROR_LOG=/dev/stderr
      - KONG_ADMIN_ERROR_LOG=/dev/stderr
    volumes:
      - ./kong:/kong:ro
    ports:
      - "8000:8000"
      - "8001:8001"
    networks:
      - lab-net
    depends_on:
      forgejo:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "kong", "health"]
      interval: 10s
      timeout: 5s
      retries: 5
EOF
```

---

### 1.5 — Avvio dello stack e verifica sanita'

```bash
cd ~/apiguard-assurance

# Avvio in background
docker compose up -d

# Attendi che tutti i container raggiungano lo stato healthy.
# Il primo avvio puo' richiedere 2-3 minuti per il pull delle immagini.
watch -n 5 docker compose ps
# Interrompi con Ctrl+C quando tutti mostrano (healthy)

# Verifica 1: Kong Admin API risponde
curl -s http://localhost:8001/ | python3 -m json.tool | head -8

# Verifica 2: Kong Proxy instrada correttamente verso Forgejo
# Attesi: 200 (ricerca pubblica abilitata) oppure 401
curl -s -o /dev/null -w "Kong proxy status: %{http_code}\n" \
  http://localhost:8000/api/v1/repos/search

# Verifica 3: Forgejo risponde direttamente (porta di debug, non usata dal tool)
curl -s -o /dev/null -w "Forgejo direct status: %{http_code}\n" \
  http://localhost:3000/api/v1/repos/search
```

---

### 1.6 — Creazione utenti di test

Il tool necessita di tre identita' distinte per coprire il gradiente Black/Grey/White Box della metodologia:

- `thesis-admin`: ruolo amministratore (token per test Grey Box P1/P2 e White Box P3)
- `user-a` e `user-b`: utenti standard con ruoli distinti (necessari per i test BOLA del Dominio 2, che richiedono due account con risorse separate)

```bash
# Utente admin (flag --admin conferisce ruolo site administrator in Forgejo)
docker exec -it --user git forgejo \
  forgejo admin user create \
  --username thesis-admin \
  --password Admin1234! \
  --email admin@test.local \
  --admin

# Utente standard A
docker exec -it --user git forgejo \
  forgejo admin user create \
  --username user-a \
  --password UserA1234! \
  --email usera@test.local

# Utente standard B
docker exec -it --user git forgejo \
  forgejo admin user create \
  --username user-b \
  --password UserB1234! \
  --email userb@test.local

# Verifica: autenticazione Basic Auth deve restituire 200
curl -s -o /dev/null -w "Admin auth: %{http_code}\n" \
  -u thesis-admin:Admin1234! \
  http://localhost:3000/api/v1/user

curl -s -o /dev/null -w "User-A auth: %{http_code}\n" \
  -u user-a:UserA1234! \
  http://localhost:3000/api/v1/user
```

---

## PARTE 2 — Scaffolding del Tool Python

### 2.1 — Inizializzazione Git e struttura directory

La struttura rispecchia esattamente il layout definito in `Implementazione.md`. La regola che guida ogni directory e' il **dominio di responsabilita'**: `core/` non sa che `tests/` esiste; `tests/` importa da `core/`; `engine.py` coordina entrambi.

```bash
cd ~/apiguard-assurance

# Inizializzazione repository Git
git init
git config user.email "thesis@apiguard.local"
git config user.name "APIGuard Thesis"

# Entry point e orchestratore (nella root di src/)
touch src/__init__.py
touch src/cli.py
touch src/engine.py

# Layer core: infrastruttura condivisa, zero logica di test
mkdir -p src/core
touch src/core/__init__.py
touch src/core/client.py
touch src/core/context.py
touch src/core/evidence.py
touch src/core/dag.py
touch src/core/models.py
touch src/core/exceptions.py

# Layer config: caricamento e validazione configurazione
mkdir -p src/config
touch src/config/__init__.py
touch src/config/schema.py
touch src/config/loader.py

# Layer discovery: comprensione della superficie d'attacco
mkdir -p src/discovery
touch src/discovery/__init__.py
touch src/discovery/openapi.py
touch src/discovery/surface.py

# Layer tests: implementazioni per dominio
mkdir -p src/tests
touch src/tests/__init__.py
touch src/tests/base.py
touch src/tests/registry.py
touch src/tests/strategy.py

# Sottodirectory per i singoli domini (0-7)
for domain in 0 1 2 3 4 5 6 7; do
  mkdir -p src/tests/domain_${domain}
  touch src/tests/domain_${domain}/__init__.py
done

# Layer report: aggregazione e rendering
mkdir -p src/report/templates
touch src/report/__init__.py
touch src/report/builder.py
touch src/report/renderer.py

# Suite E2E (non unit test, nessun mock)
mkdir -p tests_e2e
touch tests_e2e/__init__.py
touch tests_e2e/conftest.py
touch tests_e2e/test_full_pipeline.py

# File di configurazione alla root del progetto
touch config.yaml
touch pyproject.toml
touch .gitignore

# Verifica alberatura
find . -not -path './.git/*' | sort
```

---

### 2.2 — `.gitignore`

```bash
cat > ~/apiguard-assurance/.gitignore << 'EOF'
# Python bytecode
__pycache__/
*.py[cod]
*$py.class
*.pyc

# Virtual environments
.venv/
venv/
env/
ENV/

# Distribution / packaging
dist/
build/
*.egg-info/
*.egg
MANIFEST

# Installer logs
pip-log.txt
pip-delete-this-directory.txt

# Unit test / coverage reports
htmlcov/
.tox/
.nox/
.coverage
.coverage.*
coverage.xml
*.cover
*.py,cover
.hypothesis/
.pytest_cache/
nosetests.xml

# Tool outputs (generated at runtime, never committed)
evidence.json
assessment_report.html
*.log

# Secrets and local config overrides
# config.yaml is committed as a template with no real credentials.
# Real credentials are always injected via environment variables.
config.local.yaml
.env
.env.*
!.env.example

# IDE and editor artifacts
.idea/
.vscode/
*.swp
*.swo
*~
.DS_Store
Thumbs.db

# mypy
.mypy_cache/
.dmypy.json
dmypy.json

# Ruff cache
.ruff_cache/

# Docker (compose override files with local secrets)
docker-compose.override.yml
docker-compose.local.yml
EOF
```

---

### 2.3 — `pyproject.toml`

Il file definisce l'intero progetto usando il backend `hatchling` (standard PEP 517/518, nessuna dipendenza da `setup.py` legacy). Le dipendenze riflettono esattamente i moduli citati in `Implementazione.md`, con versioni minime pinned per riproducibilita'.

```bash
cat > ~/apiguard-assurance/pyproject.toml << 'EOF'
[build-system]
requires = ["hatchling>=1.21"]
build-backend = "hatchling.build"

[project]
name = "apiguard-assurance"
version = "1.0.0"
description = "Automated security assessment tool for REST APIs in Cloud environments."
readme = "README.md"
requires-python = ">=3.11"
license = { text = "MIT" }

# Runtime dependencies — grouped by architectural layer for traceability.
dependencies = [
    # HTTP client: async-capable, used exclusively via SecurityClient wrapper.
    # No test module is allowed to import httpx directly.
    "httpx>=0.27",

    # Data validation and settings management (Pydantic v2 only).
    # TargetContext uses model_config = {"frozen": True}.
    "pydantic>=2.7",
    "pydantic-settings>=2.3",

    # YAML parsing for config.yaml loading.
    "PyYAML>=6.0",

    # OpenAPI spec fetching, $ref dereferencing, and validation.
    "prance>=23.6",
    "openapi-spec-validator>=0.7",

    # Structured logging (JSON output, bound context propagation).
    # No module uses print() or stdlib logging directly.
    "structlog>=24.1",

    # Rich terminal output for CLI progress and status display.
    "rich>=13.7",

    # CLI framework: declarative argument parsing with type safety.
    "typer>=0.12",

    # Jinja2 for HTML report rendering from templates.
    "Jinja2>=3.1",

    # Retry logic with exponential backoff for SecurityClient.
    "tenacity>=8.3",
]

[project.scripts]
# Exposes the CLI entry point after `pip install -e .`
apiguard = "src.cli:app"

[tool.hatch.build.targets.wheel]
packages = ["src"]

# ---------------------------------------------------------------------------
# Development dependencies: tooling only, never imported at runtime.
# ---------------------------------------------------------------------------
[tool.hatch.envs.dev]
dependencies = [
    # End-to-end test runner against real target (no mocks).
    "pytest>=8.2",
    "pytest-asyncio>=0.23",

    # HTTP response recording for E2E test fixtures (optional, real server only).
    "pytest-httpx>=0.30",

    # Static type checking.
    "mypy>=1.10",

    # Linter and formatter (replaces flake8 + isort + black).
    "ruff>=0.4",
]

# ---------------------------------------------------------------------------
# Ruff: linting and formatting configuration.
# Target Python 3.11 syntax, strict ruleset appropriate for academic work.
# ---------------------------------------------------------------------------
[tool.ruff]
target-version = "py311"
line-length = 100
src = ["src", "tests_e2e"]

[tool.ruff.lint]
# E/W: pycodestyle, F: pyflakes, I: isort, N: pep8-naming,
# UP: pyupgrade, B: flake8-bugbear, S: flake8-bandit (security),
# ANN: flake8-annotations (enforces type hints on all signatures).
select = ["E", "W", "F", "I", "N", "UP", "B", "S", "ANN"]
ignore = [
    # ANN101/ANN102: missing type annotation for `self`/`cls` — not required.
    "ANN101",
    "ANN102",
    # S101: use of `assert` — acceptable in E2E test files only.
    "S101",
]

[tool.ruff.lint.per-file-ignores]
# E2E tests are allowed to use assert statements and some bandit-flagged calls.
"tests_e2e/*" = ["S101", "S106", "ANN"]

[tool.ruff.format]
quote-style = "double"
indent-style = "space"

# ---------------------------------------------------------------------------
# Mypy: strict type checking configuration.
# ---------------------------------------------------------------------------
[tool.mypy]
python_version = "3.11"
strict = true
warn_return_any = true
warn_unused_ignores = true
disallow_untyped_defs = true
disallow_incomplete_defs = true
check_untyped_defs = true
no_implicit_reexport = true
show_error_codes = true

# ---------------------------------------------------------------------------
# Pytest: test discovery and async mode configuration.
# ---------------------------------------------------------------------------
[tool.pytest.ini_options]
testpaths = ["tests_e2e"]
asyncio_mode = "auto"
# Markers for selective execution (e.g., pytest -m p0 for critical tests only)
markers = [
    "p0: Priority 0 tests — Black Box, no credentials required",
    "p1: Priority 1 tests — Grey Box, requires valid JWT tokens",
    "p2: Priority 2 tests — Grey Box/White Box, application logic",
    "p3: Priority 3 tests — White Box, configuration audit",
    "domain_0: API Discovery and Inventory Management",
    "domain_1: Identity and Authentication",
    "domain_2: Authorization and Access Control",
    "domain_3: Data Integrity",
    "domain_4: Availability and Resilience",
    "domain_5: Visibility and Auditing",
    "domain_6: Configuration and Hardening",
    "domain_7: Business Logic and Sensitive Flows",
]
EOF
```

---

## Chiusura: Logica delle Scelte

**Perche' `hatchling` e non `setuptools`?** Hatchling e' il build backend di riferimento per progetti moderni PEP 517/518. Non richiede `setup.py`, separa nettamente metadati e build logic, ed e' quello raccomandato dalla documentazione ufficiale di PyPA dal 2023 in poi.

**Perche' `tenacity` invece di `httpx`'s built-in retry?** `httpx` non ha retry nativo. `tenacity` permette di definire policy di backoff esponenziale con jitter e condizioni di retry personalizzate (es. riprova solo su `503`, non su `401`), che e' esattamente il comportamento descritto per `SecurityClient` in `Implementazione.md`.

**Perche' `prance` per la dereferenziazione OpenAPI?** `prance` e' l'unica libreria Python matura che risolve `$ref` remoti (HTTP e filesystem) e produce una spec completamente inline. `openapi-spec-validator` valida ma non dereferenzia; usarle in sequenza (prima `prance`, poi validazione) e' il pattern descritto in `Implementazione.md` sezione 4.2.

**Perche' i marker pytest con priorita'?** Permettono di eseguire solo i test P0 in CI (`pytest -m p0`) senza modificare il codice, replicando esattamente il filtro `min_priority` configurabile nel `config.yaml`.

---

Attendo il tuo via libera esplicito. Il prossimo step logico e' `src/core/exceptions.py` (la gerarchia delle eccezioni custom), che e' il modulo senza dipendenze interne e quindi il corretto punto di partenza bottom-up.