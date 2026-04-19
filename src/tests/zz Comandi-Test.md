# Comandi Demo — Test 4.1 Rate Limiting

Tutti i comandi si eseguono dalla root del progetto. L'ambiente è in
`test-environments/forgejo-kong/`.

---

## Abilitare il rate limiting (PASS)

Aggiungere il blocco `plugins` a `test-environments/forgejo-kong/kong/kong.yml`:

```yaml
    plugins:
      - name: rate-limiting
        config:
          minute: 100
          policy: local           # unica opzione in DB-less
          limit_by: ip            # IP TCP reale, non X-Forwarded-For
          hide_client_headers: false
          fault_tolerant: true
```

Poi ricaricare Kong e verificare:

```bash
docker compose -f test-environments/forgejo-kong/docker-compose.yml restart kong

# Verifica: devono comparire gli header X-RateLimit-*
curl -si http://localhost:8000/api/v1/activitypub/actor | grep -i ratelimit
```

---

## Disabilitare il rate limiting (FAIL)

Rimuovere il blocco `plugins` da `kong.yml`, poi:

```bash
docker compose -f test-environments/forgejo-kong/docker-compose.yml restart kong
```

---

## Eseguire il test

```bash
python -m src.cli run
```

- **Con plugin:** `Test 4.1 → PASS`
- **Senza plugin:** `Test 4.1 → FAIL` (2 finding: rate limiting assente + spoofing vulnerability)