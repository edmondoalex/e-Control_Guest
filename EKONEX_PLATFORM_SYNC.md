## Handoff corrente - baseline locale completata (10/11/2026)

CHANGE-2026-058 implementata nel repository owner fino al gate locale. Realizzati
pacchetto Hassio legacy, processi ASGI separati per amministrazione Ingress e
Guest, SQLite, token memorizzati come digest autenticato, PIN Argon2id, sessioni
brevi firmate e revocabili, CSRF/cookie dispositivo, rate limit, audit HMAC
concatenato, policy fail-closed, broker di comandi tipizzati e importatore di
dashboard/vista/card con snapshot revisionato.

File principali: `app/admin_api.py`, `app/guest_api.py`, `app/storage.py`,
`app/audit.py`, `app/policy.py`, `app/importer.py`, `app/__main__.py`,
`tests/test_security_baseline.py`, `Dockerfile`, `config.json`.

Test: `python -m pytest -q` -> 6 passed. Compilazione Python:
`python -m compileall -q app` -> superata. Test esclusivamente simulati con
adapter fittizio; nessun accesso o comando a impianti reali.

Compatibilita: integrazione diretta con Supervisor/Home Assistant legacy; nessuna
dipendenza da e-Face o dal nuovo e-Control. Il browser Guest non riceve token
Supervisor e non dispone di endpoint generici per servizi.

Rischi residui/gate: prima della distribuzione servono build e qualifica su una
VM Hassio compatibile, verifica proxy HTTPS e revisione UX. Push, release,
catalogo e installazione non eseguiti e richiedono autorizzazione esplicita.

Prossimo passo: gate del proprietario per pubblicazione/qualifica della prima
candidata; successivamente eventuale installazione pilota separatamente
autorizzata.
