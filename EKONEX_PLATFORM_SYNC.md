## Handoff corrente - RC2 pubblicata e qualificata (10/11/2026)

CHANGE-2026-058 implementata nel repository owner fino al gate locale. Realizzati
pacchetto Hassio legacy, processi ASGI separati per amministrazione Ingress e
Guest, SQLite, token memorizzati come digest autenticato, PIN Argon2id, sessioni
brevi firmate e revocabili, CSRF/cookie dispositivo, rate limit, audit HMAC
concatenato, policy fail-closed, broker di comandi tipizzati e importatore di
dashboard/vista/card con snapshot revisionato.

File principali: `app/admin_api.py`, `app/guest_api.py`, `app/storage.py`,
`app/audit.py`, `app/policy.py`, `app/importer.py`, `app/__main__.py`,
`tests/test_security_baseline.py`, `Dockerfile`, `config.json`.

Test: `python -m pytest -q` -> 12 passed. Compilazione Python:
`python -m compileall -q app` -> superata. Test esclusivamente simulati con
adapter fittizio; nessun accesso o comando a impianti reali.

Compatibilita: integrazione diretta con Supervisor/Home Assistant legacy; nessuna
dipendenza da e-Face o dal nuovo e-Control. Il browser Guest non riceve token
Supervisor e non dispone di endpoint generici per servizi.

Pubblicazione: repository `edmondoalex/e-Control_Guest`, branch `main`, candidata
`v0.1.0-rc2`, commit `844feba`. RC2 aggiunge allowlist degli attributi Guest,
proxy fidati e ripresa della sessione UI. GitHub Actions su branch e tag ha
superato compilazione, test, validazione metadati e build Docker amd64; run tag
RC2 `42822751353`.

Rischi residui/gate: restano da verificare proxy HTTPS e UX su una VM Hassio
compatibile. Catalogo e installazione non eseguiti e richiedono autorizzazione
esplicita. Nessun accesso o comando su impianti reali.

Prossimo passo: gate del proprietario per inserimento nel catalogo e, con gate
separato, installazione pilota.
