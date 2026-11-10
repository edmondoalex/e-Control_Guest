## Handoff corrente - RC4 installata e avviata (10/11/2026)

CHANGE-2026-058 implementata nel repository owner fino al gate locale. Realizzati
pacchetto Hassio legacy, processi ASGI separati per amministrazione Ingress e
Guest, SQLite, token memorizzati come digest autenticato, PIN Argon2id, sessioni
brevi firmate e revocabili, CSRF/cookie dispositivo, rate limit, audit HMAC
concatenato, policy fail-closed, broker di comandi tipizzati e importatore di
dashboard/vista/card con snapshot revisionato.

File principali: `e_control_guest/app/admin_api.py`,
`e_control_guest/app/guest_api.py`, `e_control_guest/app/storage.py`,
`e_control_guest/app/audit.py`, `e_control_guest/app/policy.py`,
`e_control_guest/app/importer.py`, `e_control_guest/app/__main__.py`,
`e_control_guest/tests/`, `e_control_guest/Dockerfile` e
`e_control_guest/config.json`.

Test: `python -m pytest -q` -> 12 passed. Compilazione Python:
`python -m compileall -q app` -> superata. Test esclusivamente simulati con
adapter fittizio; nessun accesso o comando a impianti reali.

Compatibilita: integrazione diretta con Supervisor/Home Assistant legacy; nessuna
dipendenza da e-Face o dal nuovo e-Control. Il browser Guest non riceve token
Supervisor e non dispone di endpoint generici per servizi.

Pubblicazione: repository `edmondoalex/e-Control_Guest`, branch `main`, candidata
valida `v0.1.0-rc4`, commit `df8276d`. RC2 ha introdotto gli hardening Guest;
RC4 organizza il pacchetto nella struttura repository Home Assistant con
`repository.yaml` e ripristina il bit eseguibile dell'entrypoint. RC3 e stata
superseded dopo il fallimento del controllo sul bit eseguibile. GitHub Actions
RC4 ha superato compilazione, 12 test, metadati e build Docker amd64; run tag
`42823269208`. Il branch `main` include inoltre guida operativa e discovery test
da radice al commit `a6696cd`, qualificato dal run `42823504924`.

Rischi residui/gate: restano da verificare proxy HTTPS e UX su una VM Hassio
compatibile. Catalogo e installazione non eseguiti e richiedono autorizzazione
esplicita. Nessun accesso o comando su impianti reali.

Prossimo passo: gate del proprietario per inserimento nel catalogo e, con gate
separato, installazione pilota.

Aggiornamento del proprietario: RC4 installata e avviata. Installazione e avvio
non sono ancora accettazione funzionale. Prossimo passo: collaudo read-only di
Ingress, persistenza, creazione profilo/link, accesso Guest HTTPS, revoca e
integrita audit. Comandi reali esclusi fino a indicazione esplicita.
