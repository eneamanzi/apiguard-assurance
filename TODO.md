### Fase 3: Il Grande Refactoring (Smembrare Schema e Models)
**Questo DEVE essere l'ultimo passo assoluto.** Lo si fa solo quando il codice è stabile e funziona tutto (il cosiddetto "Code Freeze").
1. Vai nella chat del refactoring.
2. Incollagli i tuoi `schema.py` e `models.py` completi e definitivi (che ora conterranno le InfoNotes e i parametri dell'Evidence).
3. Fagli eseguire il lavoro di chirurgia: dividere tutto in cartelle (`src/config/schema/domain_1.py`, ecc.) e aggiornare il `config.yaml` mettendo `test_1_1` al posto giusto.
4. Fai girare l'engine. Se tutto parte senza errori di importazione, hai vinto. Hai un'architettura Enterprise pulitissima.