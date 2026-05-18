# Scenario di test

## Requisiti Scenario - Requisiti dell'Applicazione Target

### Gruppo A - Obbligatori

**Nota infrastrutturale: tutte le applicazioni candidate verranno deployate dietro Kong API Gateway o un API gateway, configurato come punto di ingresso unico per i test dei Domini 0 e 4 della metodologia.**

* **A1** Specifica OpenAPI/Swagger completa, scaricabile e verificata in CI  
* **A2** Autenticazione via token Bearer (JWT o OAuth2) con endpoint espliciti di login, logout e refresh  
* **A3** RBAC con almeno 3 ruoli gerarchici predefiniti, configurabili senza modificare il codice  
* **A4** API REST pura (JSON, metodi HTTP standard, status code semantici)  
* **A5** Self-hostable \- Deployabile su Kubernetes (Helm chart) o Docker Compose  
* **A6** Licenza Open Source approvata OSI (MIT, Apache 2.0, AGPL)

### Gruppo B - Fortemente consigliati

* **B1** Webhook o chiamate verso URL esterni configurabili dall'utente (necessari per testare SSRF)  
* **B2** Operazioni distruttive via API (DELETE su risorse critiche con controllo di privilegio separato)  
* **B3** Multi-tenancy o isolamento tra risorse di entità diverse (prerequisito per test BOLA realistici)  
* **B4** Session store esterno (Redis o DB) anziché memoria in-process (necessario su cluster multi-replica)

### Gruppo C - Da evitare

* **C1** Spec OpenAPI generata dinamicamente senza garanzie di completezza  
* **C2** Sistemi di permessi basati su policy JSON arbitrarie anziché ruoli predefiniti  
* **C3** Protocolli ibridi non-REST (OCS, HAL+JSON, WebDAV)  
* **C4** Dipendenze da servizi SaaS esterni obbligatori

## **APP rilevanti trovate**
* Nextcloud (API non-REST pura, OCS incompatibile con la metodologia),  
* Gitea/Forgejo.  
* Mattermost  
* Harbor