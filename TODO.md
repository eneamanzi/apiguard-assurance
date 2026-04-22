### Fase 3: Il Grande Refactoring (Smembrare Schema e Models)
**Questo DEVE essere l'ultimo passo assoluto.** Lo si fa solo quando il codice è stabile e funziona tutto (il cosiddetto "Code Freeze").
1. Vai nella chat del refactoring.
2. Incollagli i tuoi `schema.py` e `models.py` completi e definitivi (che ora conterranno le InfoNotes e i parametri dell'Evidence).
3. Fagli eseguire il lavoro di chirurgia: dividere tutto in cartelle (`src/config/schema/domain_1.py`, ecc.) e aggiornare il `config.yaml` mettendo `test_1_1` al posto giusto.
4. Fai girare l'engine. Se tutto parte senza errori di importazione, hai vinto. Hai un'architettura Enterprise pulitissima.

### Il mio consiglio per stasera
Alle 21:00, non cercare di fare tutto insieme. Prendi la **Fase 1** e chiudila. Poi prenditi una pausa. Poi attacca la **Fase 2**. 
Il refactoring (Fase 3) possiamo anche lasciarlo a domani a mente fresca, tanto è solo uno spostamento di codice che già funziona.

Sei d'accordo con questo piano d'attacco? Se sì, appena scocca l'ora X parti con le InfoNotes e fammi sapere se il box azzurro compare a schermo!