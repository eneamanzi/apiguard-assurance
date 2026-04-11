### 1. La Gerarchia Principale (L'Albero dei Risultati)

Questa è la struttura che contiene gli esiti dei test e che alla fine andrà a formare il tuo JSON compatto.

* **`ResultSet` (Il Contenitore Globale)**: È la radice dell'albero. Rappresenta l'intera esecuzione della pipeline e contiene una lista di oggetti `TestResult`, oltre a calcolare l'Exit Code finale (0, 1 o 2).
* **`TestResult` (Il Singolo Test)**: Rappresenta l'esito di un test specifico (es. Test 1.1). Oltre ai metadati (nome, status, priorità), questo oggetto "possiede" due liste cruciali: la lista dei `findings` e la lista del `transaction_log`.
* **`Finding` (L'Evidenza del Danno)**: Presente solo se il test fallisce (Status = FAIL). Descrive la vulnerabilità trovata (CWE, descrizione tecnica). Ogni finding ha un campo `evidence_ref` (es. `"1.1_005"`) che serve come "gancio" per trovare la prova cruda nel file esterno.

### 2. Il Doppio Binario dei Log (Il vero colpo di genio)

Come discutevamo prima, la gestione del traffico HTTP è divisa in due modelli distinti per risolvere il problema del "peso" dei dati. Entrambi condividono lo stesso `record_id` per potersi rintracciare a vicenda.

* **`TransactionSummary` (L'Airbag / Log Ibrido)**: 
    * **Dove vive:** Dentro la lista `transaction_log` di ogni `TestResult`.
    * **Cosa contiene:** I metadati della richiesta e i payload troncati (2000 caratteri per la request, 1000 per la response). Ignora gli header di risposta.
    * **Quando viene creato:** Per **TUTTE** le richieste HTTP (PASS, FAIL, errori). 
* **`EvidenceRecord` (La Scatola Nera)**:
    * **Dove vive:** Viene salvato separatamente dal motore in un `EvidenceStore` che poi diventerà il file `evidence.json`. Non fa parte della struttura principale del report.
    * **Cosa contiene:** La transazione completa, byte per byte, con tutti gli header di risposta e i body enormi (fino a 10.000 caratteri).
    * **Quando viene creato:** SOLO per le richieste che generano un FAIL (o se esplicitamente richiesto dal test).

### Lo schema visivo delle relazioni

Per semplificare, immagina che a fine scansione l'architettura in memoria sia esattamente questa:

```text
ResultSet  (L'intera Scansione)
│
└── TestResult  (Es. Test 1.1)
    │
    ├── findings: [ Finding, Finding ]  <-- (Spiegano la vulnerabilità)
    │             │
    │             └── evidence_ref: "1.1_005" ──────┐ (Il link alla prova cruda)
    │                                               │
    └── transaction_log: [                          │
          TransactionSummary (PASS - Leggero),      │
          TransactionSummary (FAIL - Leggero)       │
            └── record_id: "1.1_005"                │
        ]                                           │
                                                    │
====================================================│=======
evidence.json  (Archivio Forense Esterno)           │
====================================================│=======
EvidenceStore                                       │
└── EvidenceRecord (Il Dump Completo)  <────────────┘
      └── record_id: "1.1_005"
```

### Come si collega questo al "ReportData"?

Nel tuo file `src/report/builder.py` (che non è qui, ma ne conosciamo il comportamento), il codice fa un'ultima cosa: prende il `ResultSet` e lo infila dentro un oggetto chiamato `ReportData`. Il `ReportData` è letteralmente solo una "copertina" che aggiunge i metadati per l'HTML (come il target URL, il nome dell'API, il tempo impiegato) e raggruppa i `TestResult` per dominio.


### 1. Separazione delle Responsabilità (Operational vs Presentation)
Il `ResultSet` è l'oggetto "vivo" usato dall'**Engine** durante l'esecuzione. Contiene le logiche per calcolare l'exit code e gestire la lista dei risultati man mano che arrivano.
`ReportData`, invece, è un oggetto "statico" (un DTO - Data Transfer Object) progettato esclusivamente per il **Renderer**. Non gli interessa come i test sono stati eseguiti, ma solo come devono essere mostrati.

### 2. Arricchimento dei Metadati
Se guardi bene, `ReportData` contiene informazioni che il `ResultSet` non ha e non dovrebbe avere:
* **Contesto del Report:** `run_id`, `generated_at_utc`, `target_base_url`.
* **Informazioni di Business:** `spec_title`, `spec_version`, `strategies_label`.
* **Raggruppamento Semantico:** Mentre `ResultSet` tiene una lista piatta di test, `ReportData` raggruppa i test per **Domini** (Domain 0, Domain 1, ecc.). Questa logica di raggruppamento serve solo alla UI ed è meglio che stia nel builder del report piuttosto che nel core dell'engine.

### 3. La catena della Verità (SSOT)
Hai ragione nel dire che tutto parte dal `ResultSet`. Il flusso è questo:
1.  **ResultSet** (SSOT dell'Esecuzione): Contiene i `TestResult`.
2.  Ogni **TestResult** contiene i **TransactionSummary** (i log ridotti).
3.  Il **TransactionSummary** ha un `record_id` che punta all'**EvidenceRecord** (il log completo nel file esterno).

`ReportData` non è una "nuova" verità, è semplicemente **la fotografia finale** del `ResultSet` pronta per essere consumata dall'HTML o dal JSON compatto.


### In sintesi:
* **ResultSet:** È il SSOT della **logica**. Serve al tool per sapere se la build deve fallire o meno.
* **ReportData:** È il SSOT della **comunicazione**. Serve all'auditor (umano o macchina) per capire cosa è successo, con tutti i fronzoli estetici e contestuali necessari.
* **EvidenceStore:** È il SSOT della **forense**. È la cassaforte che contiene i dettagli che pesano troppo per stare negli altri due.

Senza `ReportData`, saresti costretto a "sporcare" il core del tuo engine con informazioni che servono solo al sito web (come il titolo delle specifiche API o la formattazione dei tempi), rendendo il codice molto più difficile da mantenere.

1. L'Engine esegue il test e popola il `ResultSet` (con `TransactionSummary` e `Finding`).
2. Il `builder.py` prende il `ResultSet`, legge i dati, ci affianca le traduzioni in testo (nomi, label, percentuali) e impacchetta tutto dentro `ReportData`. Nessun dato vitale viene scartato.
3. Il rendering HTML (o l'esportazione JSON che implementerai) prende `ReportData` e lo stampa.
