### Roadmap implementativa basata sul DAG

### FASE A — Batch 1 Completo (Nessuna dipendenza / Baseline)
*Test strutturali e audit di configurazione che possono girare immediatamente senza richiedere un setup complesso di stato o di autenticazione.*

* **0.1** `[ TODO ]` `[Black Box]` `[P0]` : *Tutti gli Endpoint Esposti Sono Documentati e Autorizzati (Shadow API)*
* **0.2** `[ TODO ]` `[Black Box]` `[P0]` : *Il Gateway Rifiuta Richieste a Path Non Registrati (Deny-by-Default)*
* **0.3** `[ TODO ]` `[Black Box]` `[P0]` : *Le API Deprecate Sono Disabilitate o Monitorate*
* **1.1** `[  OK  ]` `[Black Box]` `[P0]` : *Solo Richieste Autenticate Accedono a Risorse Protette*
* **1.5** `[ TODO ]` `[White Box]` `[P2]` : *Le Credenziali Non Sono Trasmesse via Canali Insicuri (Audit canali)*
* **1.6** `[ TODO ]` `[White Box]` `[P3]` : *Le Sessioni Sono Gestite in Modo Sicuro in Architetture Distribuite*
* **3.3** `[  OK  ]` `[White Box]` `[P3]` : *I Dati in Transit Sono Protetti da Manipolazione (HMAC audit)*
* **4.1** `[  OK  ]` `[Black Box]` `[P0]` : *Il Sistema Previene Resource Exhaustion via Rate Limiting*
* **4.2** `[  OK  ]` `[Grey Box ]` `[P1]` : *Il Sistema Implementa Timeout per Prevenire Resource Lock (via kong_admin)*
* **4.3** `[  OK  ]` `[Grey Box ]` `[P1]` : *Il Sistema Degrada Gracefully con Circuit Breaker (via kong_admin)*
* **6.2** `[  OK  ]` `[White Box]` `[P3]` : *Security Header Configurati Appropriatamente*
* **6.4** `[  OK  ]` `[White Box]` `[P2]` : *Le Credenziali di Servizio Non Sono Hardcoded o Esposte*
* **7.2** `[  OK  ]` `[Black Box]` `[P0]` : *Il Sistema Previene Server-Side Request Forgery (Usa ssrf_payloads.py)*

### FASE B — Sblocco Autenticazione (Dipendono da 1.1 / 1.2)
*Il pivot del DAG. Una volta implementato l'helper per il forging dei JWT, si sbloccano i test avanzati sull'identità e gli allarmi di frontiera.*

* **1.2** `[ TODO ]` `[Grey Box ]` `[P0]` : *Le Credenziali Sono Crittograficamente Valide (Pivot: usa auth.py + jwt_forge.py)*
* **1.3** `[ TODO ]` `[Black Box]` `[P0]` : *Le Credenziali Non Sono Scadute (Usa jwt_forge.py)*
* **1.4** `[ TODO ]` `[Grey Box ]` `[P1]` : *Le Credenziali Non Sono State Revocate (Usa jwt_forge.py)*
* **5.2** `[ TODO ]` `[Grey Box ]` `[P2]` : *Eventi Security Anomali Triggerano Alert Real-Time (Dipende da 1.1)*
* **6.3** `[ TODO ]` `[Grey Box ]` `[P1]` : *Configurazione del Gateway Hardenata Contro Exploit Layer-7 (Dipende da 1.1)*

### FASE C — Dominio 2 e Logica di Business (Dipendono da 1.2)
*I test più complessi. Richiedono identità utente valide e manipolazione delle risorse interne tramite gli helper.*

* **2.1** `[ TODO ]` `[Grey Box ]` `[P1]` : *Solo Utenti Autorizzati Accedono a Endpoint Privilegiati (RBAC base)*
* **2.2** `[ TODO ]` `[Grey Box ]` `[P1]` : *Gli Utenti Accedono Solo ai Propri Dati (BOLA Prevention)*
* **2.3** `[ TODO ]` `[Grey Box ]` `[P1]` : *Le Operazioni Distruttive Richiedono Privilegi Appropriati (Destructive ops)*
* **2.4** `[ TODO ]` `[Grey Box ]` `[P1]` : *Le Policy di Autorizzazione Sono Consistenti Across Endpoint (Consistency)*
* **2.5** `[ TODO ]` `[Grey Box ]` `[P2]` : *L'API Non Espone Dati Eccessivi (Data exposure)*
* **3.1** `[ TODO ]` `[Grey Box ]` `[P2]` : *Tutti gli Input Sono Validati (Injection - usa injection_payloads.py)*
* **5.1** `[ TODO ]` `[Grey Box ]` `[P1]` : *Ogni Richiesta È Logged con Metadata Essenziali (Audit logging)*
* **6.1** `[ TODO ]` `[Grey Box ]` `[P2]` : *Error Handling e Information Disclosure (Usa response_inspector.py)*
* **7.1** `[ TODO ]` `[Grey Box ]` `[P2]` : *Flussi Business Sensibili Protetti da Abuse Automatizzato*
* **7.3** `[ TODO ]` `[Grey Box ]` `[P2]` : *Le Operazioni Critiche Sono Idempotent o Protette da Race Condition*
* **7.4** `[ TODO ]` `[Grey Box ]` `[P2]` : *L'API Consuma Servizi Esterni in Modo Sicuro (Webhook integration)*




### DOMINIO 0: API DISCOVERY E INVENTORY MANAGEMENT
* **0.1 Tutti gli Endpoint Esposti Sono Documentati e Autorizzati** (`Black Box` • `P0`)
  *Verifica che ogni endpoint risponda alla specifica OpenAPI per individuare eventuali Shadow API.*
* **0.2 Il Gateway Rifiuta Richieste a Path Non Registrati** (`Black Box` • `P0`)
  *Controlla che le chiamate verso route inesistenti ricevano un deny-by-default (404/403) senza gravare sui backend.*
* **0.3 Le API Deprecate Sono Disabilitate o Monitorate** (`Black Box` • `P0`)
  *Assicura che le vecchie versioni dell'API siano spente o sottoposte a rate limit e logging rafforzati.*

### DOMINIO 1: IDENTITÀ E AUTENTICAZIONE
* **1.1 Solo Richieste Autenticate Accedono a Risorse Protette** (`Black Box` • `P0`)
  *Intercetta tentativi di accesso anonimo verso risorse sensibili.*
* **1.2 Le Credenziali Sono Crittograficamente Valide** (`Black Box` • `P0`)
  *Forgia token malformati e firme errate per accertarsi che vengano respinti al perimetro.*
* **1.3 Le Credenziali Non Sono Scadute** (`Black Box` • `P0`)
  *Verifica l'esatta applicazione del parametro temporale `exp` per invalidare i JWT.*
* **1.4 Le Credenziali Non Sono State Revocate** (`Grey Box` • `P1`)
  *Testa i meccanismi di revoca anticipata di un token o di una API key prima della sua naturale scadenza.*
* **1.5 Le Credenziali Non Sono Trasmesse via Canali Insicuri** (`Grey/White Box` • `P2`)
  *Indaga l'esposizione accidentale di secret attraverso le query string, gli URL o canali in chiaro.*
* **1.6 Le Sessioni Sono Gestite in Modo Sicuro in Architetture Distribuite** (`White Box` • `P3`)
  *Effettua l'audit su come il cluster propaga e protegge lo stato della sessione tra i microservizi.*

### DOMINIO 2: AUTORIZZAZIONE E CONTROLLO ACCESSI
* **2.1 Solo Utenti Autorizzati Accedono a Endpoint Privilegiati** (`Grey Box` • `P1`)
  *Previene l'escalation di privilegi verticale tentando di usare token utente per route admin.*
* **2.2 Gli Utenti Accedono Solo ai Propri Dati (BOLA Prevention)** (`Grey Box` • `P1`)
  *Scambia gli identificatori (ID) nelle richieste HTTP per testare eventuali Insecure Direct Object References.*
* **2.3 Le Operazioni Distruttive Richiedono Privilegi Appropriati** (`Grey Box` • `P1`)
  *Valida il principio del least privilege assicurando che verbi come DELETE e PUT siano blindati rispetto a GET.*
* **2.4 Le Policy di Autorizzazione Sono Consistenti Across Endpoint** (`Grey Box` • `P1`)
  *Assicura l'assenza di scappatoie applicando gli stessi filtri su tutte le risorse paritetiche.*
* **2.5 L'API Non Espone Dati Eccessivi** (`Grey/White Box` • `P2`)
  *Esamina la risposta per rilevare l'over-fetching di campi interni non dichiarati e non necessari al client.*

### DOMINIO 3: INTEGRITÀ DEI DATI
* **3.1 Tutti gli Input Sono Validati Secondo Schema e Constraints** (`Grey/White Box` • `P2`)
  *Sonda i controlli di validazione (es. Type Confusion, Injection) applicati a monte della business logic.*
* **3.3 I Dati in Transit Sono Protetti da Manipolazione** (`White Box` • `P3`)
  *Accerta la presenza di firme interne o validazioni d'integrità del payload al di là della banale cifratura TLS.*

### DOMINIO 4: DISPONIBILITÀ E RESILIENZA
* **4.1 Il Sistema Previene Resource Exhaustion via Rate Limiting** (`Black Box` • `P0`)
  *Esegue spike di traffico per verificare il blocco (es. 429 Too Many Requests) prima del crash dei servizi.*
* **4.2 Il Sistema Implementa Timeout per Prevenire Resource Lock** (`Grey Box` • `P1`)
  *Esamina il rilascio forzato di connessioni bloccanti ed eccessivamente lunghe.*
* **4.3 Il Sistema Degrada Gracefully con Circuit Breaker** (`Grey Box` • `P1`)
  *Legge le metriche per validare la presenza dello sgancio automatico dai backend irraggiungibili per impedire guasti a catena.*

### DOMINIO 5: VISIBILITÀ E AUDITING
* **5.1 Ogni Richiesta È Logged con Metadata Essenziali** (`Grey Box` • `P1`)
  *Garantisce l'esistenza di tracce d'audit adeguate per la root cause analysis post-incidente.*
* **5.2 Eventi Security Anomali Triggerano Alert Real-Time** (`Grey/White Box` • `P2`)
  *Misura il tempo e la soglia di reazione dei SIEM o sistemi d'allarme di fronte a pattern ostili persistenti.*

### DOMINIO 6: CONFIGURAZIONE E HARDENING
* **6.1 Error Handling e Information Disclosure** (`Grey/White Box` • `P2`)
  *Scandaglia codici d'errore 500 per accertarsi che stack trace, versioni e query SQL non trapelino al client.*
* **6.2 Security Header Configurati Appropriatamente** (`White Box` • `P3`)
  *Analizza le testate HTTP in risposta accertandosi della presenza di policy sicure per la protezione del frontend.*
* **6.3 Configurazione del Gateway Hardenata Contro Exploit Layer-7** (`Grey Box` • `P1`)
  *Valida l'applicazione dei filtri WAF e difese generiche intercettabili dal perimetro di frontiera.*
* **6.4 Le Credenziali di Servizio Non Sono Hardcoded o Esposte** (`Grey/White Box` • `P2`)
  *Ricerca environment variables esposte o password statiche nei file architetturali e nelle configurazioni di plugin.*

### DOMINIO 7: BUSINESS LOGIC E FLUSSI SENSIBILI
* **7.1 Flussi Business Sensibili Protetti da Abuse Automatizzato** (`Grey/White Box` • `P2`)
  *Interroga le difese anti-bot (es. CAPTCHA, Challenge) per la mitigazione del Credential Stuffing su endpoint di autenticazione.*
* **7.2 Il Sistema Previene Server-Side Request Forgery (SSRF)** (`Black Box` • `P0`)
  *Inietta indirizzi IP cloud-metadata e di rete privata per scovare tentativi di aggiramento.*
* **7.3 Le Operazioni Critiche Sono Idempotent o Protette da Race Condition** (`Grey/White Box` • `P2`)
  *Assicura l'impossibilità di moltiplicare fondi o privilegi tramite richieste concorrenti ravvicinate.*
* **7.4 L'API Consuma Servizi Esterni in Modo Sicuro** (`Grey/White Box` • `P2`)
  *Analizza come il target tratta l'importazione di dipendenze, file e informazioni da vendor di terze parti.*
