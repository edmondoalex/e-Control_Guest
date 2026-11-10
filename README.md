# e-Control Guest

Repository Home Assistant per condividere singole schede di una dashboard con
ospiti, senza consegnare credenziali Home Assistant o accesso amministrativo.

[![Aggiungi il repository a Home Assistant](https://my.home-assistant.io/badges/supervisor_add_addon_repository.svg)](https://my.home-assistant.io/redirect/supervisor_add_addon_repository/?repository_url=https%3A%2F%2Fgithub.com%2Fedmondoalex%2Fe-Control_Guest)

L'amministratore seleziona dashboard, vista e scheda, approva le entità
leggibili e abilita separatamente ogni azione. Il Guest riceve un link
revocabile con scadenza, limite di sessioni e PIN opzionale.

Il pacchetto installabile è in [`e_control_guest`](e_control_guest). Le
istruzioni sono in [`e_control_guest/DOCS.md`](e_control_guest/DOCS.md).

## Sicurezza

- amministrazione esclusivamente tramite Home Assistant Ingress;
- portale Guest separato sulla porta `8100`, da pubblicare dietro HTTPS;
- token memorizzati solo come digest HMAC e PIN Argon2id;
- sessioni firmate, CSRF, cookie dispositivo, rate limit e revoca immediata;
- allowlist per scheda, entità, azione e intervallo di valore;
- nessun endpoint Guest generico per chiamare servizi Home Assistant;
- attributi Home Assistant filtrati prima di raggiungere il browser;
- audit HMAC concatenato per visite, letture, tentativi, dinieghi, comandi e
  readback.

## Verifica

```text
python -m pip install -r e_control_guest/requirements-dev.txt
python -m pytest -q
python -m compileall -q e_control_guest/app e_control_guest/tests
```

La CI esegue anche la build completa dell'immagine `linux/amd64`.
