Parametri per API

> Ciao! Stiamo lavorando allo sviluppo di **APIGuard**, il nostro framework DAST. Dobbiamo implementare definitivamente il test **4.3 (Circuit Breaker Configuration Audit)** del Dominio 4 (Resilienza) su un API Gateway Kong (OSS/DB-less).
> 
> Abbiamo già completato l'analisi metodologica. Poiché Kong OSS non dispone di un plugin "circuit-breaker" nativo (presente solo in Enterprise), abbiamo architettato un approccio **"Dual-Check" a 3 Livelli** per evitare falsi negativi e documentare correttamente i controlli compensativi.
> 
> **La Metodologia (Logica del Test):**
> * **LIVELLO 1 (Nativo):** Cerca il plugin `"circuit-breaker"` (tramite l'helper `get_plugins()`). *Nota bene: NON accettare "response-ratelimiting" in quanto gestisce i volumi, non i cascading failures*. Se il plugin nativo c'è e le sue soglie sono valide -> `PASS` (Full Guarantee).
> * **LIVELLO 2 (Compensating Control):** Se il plugin nativo non c'è, interroga l'helper `get_upstreams()`. Verifica se esiste almeno un upstream che implementa un `healthchecks.passive` configurato con soglie sicure (max failures, max timeouts, ecc.). Se sì -> `PASS` con un Finding "Informativo/Architetturale" che documenta l'uso di un controllo compensativo parziale.
> * **LIVELLO 3 (Vulnerabile):** Se non c'è né il plugin né un upstream con passive healthcheck -> `FAIL` (Nessuna protezione da cascading failure).
> * **Finding Separato (Osservabilità):** Verifica l'endpoint `/status` per vedere se espone metriche del circuit breaker. (Questo finding è indipendente dallo status del test).
> 
> **Configurazione Richiesta (da implementare):**
> Ecco la struttura esatta che devi usare per il blocco `test_4_3` (inseriscila nel `config.yaml` e crea i relativi modelli Pydantic):
> ```yaml
>     test_4_3:
>       accepted_cb_plugin_names:
>         - "circuit-breaker"
>       failure_threshold_min: 3
>       failure_threshold_max: 10
>       timeout_duration_min_seconds: 30
>       timeout_duration_max_seconds: 120
>       passive_healthcheck:
>         http_failures_max: 5
>         timeouts_max: 3
>         successes_min: 2
>         required_unhealthy_statuses:
>           - 500
>           - 502
>           - 503
>           - 504
> ```

> 
> Se sei daccordo con tutto forniscimi i file completi e aggiornati.
***