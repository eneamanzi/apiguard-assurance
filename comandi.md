# APIGuard Assurance - Cheat Sheet Comandi
## Utility: Export
Creare uno ZIP aggiornato con tutti i sorgenti e i test (escludendo cache, pycache e report):

```bash
zip -r apiguard-assurance.zip . -x "*.git/*" -x "*__pycache__*" -x "*.pyc" -x "*.ruff_cache*" -x "*.pytest_cache*" -x "*.mypy_cache*" -x "*.vscode*" -x "*outputs*" -x "*.zip" -x ".env"
```

## Visualizzazione Report (VS Code Remote)
Avviare un server web locale per visualizzare il report HTML in tempo reale tramite il Port Forwarding:
\`\`\`bash
cd outputs
python3 -m http.server 8080
\`\`\`
*(Dopo averlo lanciato, apri il browser sul tuo PC all'indirizzo `http://localhost:8080` e clicca su `assessment_report.html`. Premi `Ctrl+C` nel terminale per spegnerlo).*


## Gestione Ambiente (Hatch)
Attivare l'ambiente virtuale:
\`\`\`bash
hatch shell dev
\`\`\`

Altrimenti anteporre "hatch run -e dev" ai comandi

## Esecuzione del Tool (CLI)
*Nota: Assicurarsi che le variabili d'ambiente (.env) siano caricate o che il file esista nella root.*
(legge config.yaml di default)

**Sviluppo (diretto):**
\`\`\`bash
python -m src.cli
\`\`\`

**Installato (se configurato in pyproject.toml):**
\`\`\`bash
apiguard run
\`\`\`
*(Questo è il "pulsante di accensione" che lancia l'intero assessment contro il target configurato).*


## Esecuzione dei Test (Pytest)

Eseguire i Test di Integrazione (Il Motore):
\`\`\`bash
pytest tests_integration/ -v
\`\`\`

Eseguire i Test End-to-End (Il Mondo Reale contro Forgejo):
\`\`\`bash
pytest tests_e2e/ -v
\`\`\`

Eseguire un singolo file di test:
\`\`\`bash
pytest tests_integration/test_05_execution.py -v
\`\`\`


## Linting e Type Checking
Controllare la formattazione e gli errori sintattici (Ruff):
\`\`\`bash
ruff check .
\`\`\`

Controllare i tipi rigorosi (Mypy):
\`\`\`bash
mypy src/ tests_integration/ tests_e2e/
\`\`\`
