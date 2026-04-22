### Roadmap implementativa basata sul DAG

Partendo dalla tabella delle dipendenze, i test si sviluppano in questo ordine naturale:

**Fase A — Batch 1 completo (tutti i test senza dipendenze)**

```
0.1 → 0.2 → 0.3   # Domain 0, già presenti nel repo
1.1               # primo test da implementare nel Domain 1                                   OK
4.1               # rate limiting, BLACK_BOX                                                  OK
7.2               # SSRF, BLACK_BOX — usa data/ssrf_payloads.py
1.5, 1.6          # WHITE_BOX audit TLS e session store
3.3               # WHITE_BOX HMAC audit
4.2, 4.3          # WHITE_BOX Kong timeout e circuit breaker — usa kong_admin.py              4.2 OK - 4.3 OK
6.2, 6.4          # WHITE_BOX header e hardcoded credentials
```

**Fase B — Sblocca il resto (dipende da `1.1` e `1.2`)**

```
1.2               # GREY_BOX — usa auth.py + jwt_forge.py, pivot dell'intero DAG
1.3, 1.4          # completamento Domain 1 — usa jwt_forge.py
5.2, 6.3          # dipendono solo da 1.1
```

**Fase C — Domain 2 e il resto dei GREY_BOX (dipendono da `1.2`)**

```
2.1               # RBAC base
2.2, 2.3, 2.4, 2.5  # BOLA, destructive ops, consistency, exposure — usano forgejo_resources.py
3.1               # injection — usa data/injection_payloads.py
5.1               # audit logging
6.1               # error handling — usa response_inspector.py
7.1, 7.3, 7.4     # business logic, race condition, webhook
```

L'ordine all'interno di ogni fase non è vincolato dal DAG — possiamo scegliere il test più semplice da fare come primo in ogni fase per validare l'infrastruttura prima di affrontare quelli complessi. Suggerisco di iniziare con `1.1` e `4.1` (i più diretti) per confermare che l'intera pipeline test→result→evidence funziona end-to-end prima di affrontare `1.2` che è il test pivot.
