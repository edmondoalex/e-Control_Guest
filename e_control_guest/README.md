# e-Control Guest

Add-on autonomo per condividere dashboard controllate di un impianto senza
consegnare agli ospiti credenziali o accesso amministrativo.

## Confini di sicurezza

- l'amministrazione e disponibile soltanto tramite Ingress;
- il portale Guest usa una porta e un'applicazione ASGI separate;
- ogni condivisione espone soltanto card, entita e azioni in allowlist;
- i token di condivisione sono casuali e nel database viene conservato solo il
  loro digest autenticato;
- i PIN sono derivati con Argon2id;
- le sessioni sono firmate, brevi, revocabili e legate alla revisione della
  condivisione;
- ogni richiesta, diniego, comando e readback entra nel registro audit HMAC
  concatenato;
- il browser Guest non riceve mai il token Supervisor o credenziali impianto.

## Porte

- `8099/tcp`: amministrazione Ingress, non pubblicata;
- `8100/tcp`: portale Guest, pubblicabile soltanto dietro HTTPS.

## Stato

Baseline locale completa per CHANGE-2026-058:

- due processi ASGI separati, con amministrazione vincolata a loopback/Ingress;
- portale Guest con sessioni firmate, cookie dispositivo HttpOnly, CSRF e revoca;
- broker tipizzato senza endpoint generico verso i servizi Home Assistant;
- snapshot revisionati di dashboard, viste e card con custom card negate;
- SQLite locale e audit HMAC concatenato verificabile;
- rate limit e idempotenza dei comandi;
- test esclusivamente simulati (`python -m pytest -q`).

Nessuna release, pubblicazione, installazione o prova su impianto reale e stata
effettuata.

## Sviluppo locale

```text
python -m pip install -r requirements-dev.txt
python -m pytest -q
```

L'avvio dell'immagine usa `python -m app`: il processo amministrativo ascolta
solo su `127.0.0.1:8099`, mentre il portale Guest ascolta sulla porta configurata.
