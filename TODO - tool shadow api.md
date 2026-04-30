I risultati preliminari sono interessanti ma mancano di dettagli specifici sui tool. Approfondisco le pagine più rilevanti per estrarre nomi concreti e caratteristiche tecniche.
Ottimi risultati. Faccio un'ultima ricerca mirata per confermare i repository GitHub e le caratteristiche tecniche dei tool specifici menzionati.
Eccellente. Ho raccolto informazioni sufficienti per fornirti una rassegna completa e strutturata.

Tool Open Source per Shadow API Discovery e API Fuzzing

La tua strategia di integrare tool esterni è solida — reinventare la ruota non ha senso quando esistono strumenti maturi e ben mantenuti. Di seguito una selezione ragionata, organizzata per categoria funzionale.

Endpoint Discovery e Route Bruteforcing

| Tool | Repository | Linguaggio | Output | Note chiave |
|------|-----------|------------|--------|-------------|
| Kiterunner | assetnote/kiterunner | Go | JSON, text | Il più indicato per Shadow API. Non si limita a bruteforce di path: negozia route con metodi HTTP multipli e gestisce pattern RESTful moderni. Wordlist dedicate da Assetnote. |
| ffuf | ffuf/ffuf | Go | JSON, CSV, HTML | Fuzzer generico ultrarapido. Ottimo per fuzzing di endpoint, parametri, header. Supporta recursion e filtri avanzati su status code, dimensione risposta, parole. |
| feroxbuster | epi052/feroxbuster | Rust | JSON, text | Alternativa a ffuf con ricorsione automatica aggressiva. Output JSON strutturato, facile da parsare. |

Esempio Kiterunner:
``bash
kr scan https://api.target.com \
  -w routes-large.kite \
  -x 4 \
  --fail-status-codes 403,429,500 \
  -o json \
  --output-file results.json
`

Parameter Discovery (Hidden Parameters)

| Tool | Repository | Linguaggio | Output | Note chiave |
|------|-----------|------------|--------|-------------|
| Arjun | s0md3v/Arjun | Python | JSON, text | Scopre parametri nascosti via heuristics e anomaly detection. Supporta GET, POST, JSON body. |
| x8 | Sh1Yo/x8 | Rust | JSON | Più veloce di Arjun, detection basata su differenze nelle risposte. |
| ParamSpider | devanshbatham/ParamSpider | Python | text | Mining di parametri da archivi web (Wayback Machine). Complementare ai fuzzer attivi. |

Esempio Arjun:
`bash
arjun -u https://api.target.com/user/update \
  -m POST \
  --stable \
  -oJ arjun-params.json
`

Schema-Driven Fuzzing (OpenAPI/Swagger)

| Tool | Repository | Linguaggio | Output | Note chiave |
|------|-----------|------------|--------|-------------|
| Schemathesis | schemathesis/schemathesis | Python | JUnit XML, JSON | Property-based testing. Genera test randomizzati ma schema-compliant. Trova edge case, crash, violazioni di specifica. Supporta OpenAPI 3.1 e GraphQL. |
| CATS | Endava/cats | Java | JSON, HTML | REST API fuzzer negativo. Genera automaticamente casi di test per boundary, malformed input, security headers. |
| APIFuzzer | KissPeter/APIFuzzer | Python | JSON | Fuzz testing da spec OpenAPI/Swagger senza scrivere codice. |
| Dredd | apiaryio/dredd | JavaScript | JUnit XML | Valida che l'implementazione rispetti la specifica. Utile per contract testing. |

Esempio Schemathesis:
`bash
schemathesis run https://api.target.com/openapi.json \
  --checks all \
  --hypothesis-phases=generate \
  --report=junit.xml
`

Vulnerability Scanning con Template (Nuclei)

| Tool | Repository | Linguaggio | Output | Note chiave |
|------|-----------|------------|--------|-------------|
| Nuclei | projectdiscovery/nuclei | Go | JSON, SARIF | Scanner template-based. Ha una libreria di template http/api/ per vulnerabilità API specifiche (BOLA, info disclosure, auth bypass). Output JSON strutturato, ideale per parsing. |

Esempio Nuclei su endpoint scoperti:
`bash
nuclei -l discovered-endpoints.txt \
  -t http/api/ \
  -severity medium,high,critical \
  -json \
  -o nuclei-results.json
`

API Discovery e Inventory (Runtime/Traffic-Based)

| Tool | Repository | Linguaggio | Output | Note chiave |
|------|-----------|------------|--------|-------------|
| Akto | akto-api-security/akto | Java | JSON API | Open source. Discovery da traffic, inventory automatico, test library OWASP. Può correlare endpoint scoperti vs specifica dichiarata. |
| APIClarity | apiclarity/apiclarity | Go | OpenAPI spec | Ricostruisce spec OpenAPI da traffico runtime. Perfetto per identificare shadow API confrontando spec generata vs spec ufficiale. |
| mitmproxy2swagger | alufers/mitmproxy2swagger | Python | OpenAPI YAML | Reverse-engineering di API da traffico catturato con mitmproxy. Genera spec da sessioni reali. |

Tool Complementari

| Tool | Repository | Uso | Output |
|------|-----------|-----|--------|
| OWASP OFFAT | OWASP/OFFAT | Assessment automatico OWASP API Top 10 | JSON |
| Astra | flipkart-incubator/Astra | Security testing REST API | HTML report |
| gotestwaf | wallarm/gotestwaf | Test bypass WAF/API Gateway | JSON |

Strategia di Integrazione per il Tuo Tool

Per la tua architettura a wrapper/adapter, suggerisco di categorizzare i tool per fase operativa:

`
┌─────────────────────────────────────────────────────────────┐
│                    DISCOVERY PIPELINE                       │
├─────────────────────────────────────────────────────────────┤
│  FASE 1: Endpoint Discovery                                 │
│  ├── Kiterunner (route bruteforce) → JSON                   │
│  ├── ffuf (path fuzzing) → JSON                             │
│  └── mitmproxy2swagger (traffic analysis) → OpenAPI YAML    │
├─────────────────────────────────────────────────────────────┤
│  FASE 2: Parameter Discovery                                │
│  ├── Arjun (hidden params) → JSON                           │
│  └── x8 (parameter fuzzing) → JSON                          │
├─────────────────────────────────────────────────────────────┤
│  FASE 3: Spec Comparison (Shadow Detection)                 │
│  └── Diff tra spec ufficiale e endpoint scoperti            │
├─────────────────────────────────────────────────────────────┤
│  FASE 4: Vulnerability Assessment                           │
│  ├── Schemathesis (schema fuzzing) → JUnit XML              │
│  └── Nuclei (template scanning) → JSON                      │
└─────────────────────────────────────────────────────────────┘
`

Formati Output e Parsing

Tutti questi tool supportano output strutturato — questo è il punto chiave per l'integrazione:

| Tool | Formato preferito | Struttura |
|------|-------------------|-----------|
| Kiterunner | JSON (-o json) | {url, method, status, length} |
| ffuf | JSON (-of json) | {results: [{url, status, length, words}]} |
| Arjun | JSON (-oJ) | {url: [params]} |
| Nuclei | JSON (-json) | {template, matched, severity, host} |
| Schemathesis | JUnit XML | Standard JUnit testcase format |

La mia raccomandazione: crea un adapter layer con Pydantic models per normalizzare l'output di ogni tool in un formato interno unificato (es. DiscoveredEndpoint, DiscoveredParameter, VulnerabilityFinding`). awesome-api-security