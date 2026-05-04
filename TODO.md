
### 🟡 FASE 2: Strategia e Mappatura (Il Nuovo Task)
*Definiamo la linea di confine esatta tra "Cervello" (Python) e "Muscoli" (Tool Esterni).*

* **[ 3 ]** Esegui la mappatura completa dei tuoi ~20 test.
* **[ 4 ]** Per ogni test, decidi l'etichetta definitiva: `[NATIVE]` (logica stateful in Python) oppure `[EXTERNAL]` (da delegare a un binario).
* *Milestone:* Lista definitiva di quali tool esterni ci serviranno (es. `ffuf`, `testssl.sh`, `arjun`).

### 🟠 FASE 3: Congelamento Architetturale
*Mettiamo a verbale la rivoluzione.*

* **[ 5 ]** Inserisci il testo dell'ADR approvato nella documentazione ufficiale (es. aggiornando `Implementazione.md` o la cartella `docs/`).
* *Milestone:* Il "contratto" di design è ufficiale e consultabile.

### 🔵 FASE 4: Costruzione delle Fondamenta (Tubi Vuoti)
*Creiamo l'infrastruttura Python per ospitare i tool, senza ancora chiamarli.*

* **[ 6 ]** Scrivi `src/connectors/base.py` (La classe astratta `BaseConnector` e il `ConnectorResult`).
* **[ 7 ]** Scrivi `src/external_tests/base.py` (La classe astratta `ExternalToolTest`).
* **[ 8 ]** Scrivi `src/external_tests/registry.py` (Il sistema di discovery).
* **[ 9 ]** Aggiorna `engine.py` per fondere le liste di discovery.
* *Milestone:* Il framework è pronto ad accogliere i tool, ma al momento gira a vuoto.

### 🟣 FASE 5: Il "Paziente Zero" (Test 0.1)
*Proviamo che tutto il sistema funziona col primo tool reale.*

* **[ 10 ]** Sviluppa `ffuf_connector.py` (implementando `BaseConnector`).
* **[ 11 ]** Scrivi `ext_test_0_1_shadow_api.py` (implementando `ExternalToolTest` e chiamando il connettore ffuf).
* *Milestone:* Il Dominio 0 è completato con fuzzing di livello Enterprise.

