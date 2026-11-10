## Handoff corrente - RC26 pubblicata, branding Ekonex e splash (10/11/2026)

Pubblicata e qualificata RC26. Il portale Guest mostra il marchio Ekonex a
destra dell'intestazione desktop; su telefono i due blocchi di marca sono
disposti uno sopra l'altro. Dopo il login compare uno splash Ekonex per almeno
5 secondi e comunque fino al completamento del caricamento della dashboard.

RC23 ha reso recuperabili e ricopiabili dall'amministrazione i link creati
dalla stessa versione o successive, senza memorizzare il token in chiaro. RC24
serve `/favicon.ico` e usa un vero form per il PIN. Gli avvisi browser relativi
a feature `Permissions-Policy` pubblicitarie non sono emessi dall'applicazione
e non bloccano il login.

Commit RC26 `24c9e08`, tag/release `v0.1.0-rc26`; 19 test, compileall,
sintassi JavaScript e diff-check locali PASS. GitHub Actions tag
`42873237159`: test, metadati e build `amd64`, `aarch64`, `armv7`, `armhf` e
`i386` PASS. Asset Ekonex preparato dall'immagine fornita dal proprietario.
Installazione e verifica visiva sull'impianto restano al proprietario.

## Handoff corrente - RC18 pubblicata, nomi Home Assistant (10/11/2026)

Pubblicata RC18. Nella configurazione dei permessi il nome principale
e ora il nome descrittivo Home Assistant (`friendly_name`), mentre l'ID entita
resta visibile sotto in piccolo come riferimento tecnico. Un nome esplicito
della scheda Lovelace conserva la priorita. Il recupero usa una sola lettura
bulk degli stati sul runtime Hassio e un fallback compatibile per gli adapter
di test; in caso di indisponibilita resta l'ID senza bloccare l'amministrazione.

La risoluzione avviene anche per schede gia importate e non modifica snapshot,
permessi o link. Il pulsante `Copia link` usa Clipboard API quando consentita e
un fallback compatibile con Home Assistant Ingress, mostrando l'esito. Un nuovo
token nell'URL prevale sempre su eventuali sessioni browser residue; una
sessione scaduta o invalida torna al login con un messaggio invece di lasciare
la dashboard vuota. Commit `55dd0a1`, tag/release `v0.1.0-rc18`; 15 test,
compileall, sintassi JavaScript e diff-check locali PASS. GitHub Actions tag
`42863075138`: test, metadati e build `amd64`, `aarch64`, `armv7`, `armhf` e
`i386` PASS. Installazione e collaudo restano al proprietario.

## Handoff corrente - RC17 pubblicata, permessi cumulativi e identita Guest (10/11/2026)

Pubblicata RC17. La pagina amministrativa offre `Salva tutti i
permessi`, con validazione e aggiornamento atomico dell'intero profilo e una
sola revisione; il salvataggio della singola scheda resta disponibile. Il
pulsante `Rimuovi` e ora visibile anche sulla scheda chiusa e richiede conferma.

Il registro risolve il nome Guest dal nome/descrizione assegnato al link anche
per letture stato e visualizzazione dashboard. L'endpoint audit arricchisce in
lettura gli eventi precedenti collegando sessione e link, senza alterare la
catena HMAC. Link storici privi di etichetta non possono acquisire
retroattivamente un'identita. Nessun token o PIN e registrato.

Commit `6e0305d`, tag/release `v0.1.0-rc17`. Qualifica locale: 15 test,
compileall, sintassi JavaScript e diff-check PASS. GitHub Actions tag
`42859931572`: test, metadati e build `amd64`, `aarch64`, `armv7`, `armhf` e
`i386` PASS. Installazione e collaudo Green restano al proprietario.

## Handoff corrente - RC16 link nominativi e audit leggibile (10/11/2026)

RC13 sostituisce il cursore del setpoint con una casella numerica; RC14 aggiunge
link senza scadenza, protetti da PIN e validi fino alla revoca. RC15 introduce
nome ospite/descrizione del link, motivazione obbligatoria, autore e data della
revoca. RC16 rende leggibile il registro Guest con nome link, dispositivo,
comando, valore richiesto, stato finale ed esito, senza registrare token o PIN.

Commit RC16 `38fe7b0`, tag/release `v0.1.0-rc16`. Qualifica locale: 15 test,
compileall e sintassi JavaScript PASS. GitHub Actions tag `42854861289`: test,
metadati e build `amd64`, `aarch64`, `armv7`, `armhf`, `i386` PASS. Le vecchie
revoche non possono acquisire retroattivamente un nome; vengono indicate come
link precedenti. Aggiornamento e collaudo UI sul Green restano al proprietario.

## Handoff precedente - RC12 permessi gestibili su profili grandi (10/11/2026)

RC12 corregge l'elenco permessi troppo esteso: ogni scheda e richiusa per
impostazione predefinita e mostra soltanto titolo e conteggio dispositivi.
Aggiunti ricerca per stanza/entita, apertura e chiusura globale e comando
rapido per impostare una scheda in sola lettura prima del salvataggio. Profili,
snapshot e configurazioni RC11 restano compatibili.

Commit `05d108d`, tag/release `v0.1.0-rc12`. Qualifica locale: 15 test,
compileall e sintassi JavaScript PASS. GitHub Actions tag `42851349210`: test,
metadati e build `amd64`, `aarch64`, `armv7`, `armhf`, `i386` PASS.
Aggiornamento e verifica UI sul Green restano al proprietario.

## Handoff precedente - RC11 layout vista e termostati (10/11/2026)

RC11 aggiunge l'importazione in blocco dell'intera vista mantenendo ordine e
intestazioni `heading`, e rende il portale Guest una griglia densa responsive.
Le entita `climate` mostrano stato, temperatura attuale e setpoint; i comandi
di temperatura e modalita HVAC restano disabilitati per impostazione
predefinita e richiedono autorizzazione separata. Le `custom:*` continuano a
essere escluse e non viene eseguito codice Lovelace non controllato.

Commit `66b495a`, tag/release `v0.1.0-rc11`. Qualifica locale: 15 test,
compileall e controllo sintassi JavaScript PASS. GitHub Actions tag
`42847705487`: metadati, test e build QEMU `amd64`, `aarch64`, `armv7`, `armhf`
e `i386` PASS. Il proprietario ha gia installato e collaudato RC10 sul Green
con Cloudflare; aggiornamento e verifica visiva RC11 restano al proprietario.

## Handoff precedente - RC10 multi-arch pubblicata e qualificata (10/11/2026)

RC10 estende il pacchetto a tutte le architetture add-on Home Assistant:
`amd64`, `aarch64`, `armv7`, `armhf` e `i386`. La build usa le immagini base
ufficiali per architettura e installa/rimuove un toolchain temporaneo quando le
dipendenze crittografiche richiedono compilazione nativa. Home Assistant Green
(`aarch64`) e quindi coperto.

Commit RC10 `4d3e38d`, tag/release `v0.1.0-rc10`. Qualifica locale: 14 test e
compileall PASS. GitHub Actions tag `42842108337`: metadati, test e build reali
QEMU per tutte e cinque le architetture PASS. RC9 e marcata non qualificata e
superseded per il precedente fallimento armv7; RC8 resta la prima candidata
qualificata amd64/aarch64. Installazione sul Green resta al proprietario.

## Handoff precedente - RC7 pubblicata, aggiornamento proprietario pendente (10/11/2026)

Durante il collaudo HTTPS il tunnel Cloudflare e il DNS
`guest-grupposomet.e-control.tech` sono risultati operativi, ma Google Safe
Browsing ha bloccato specificamente il percorso pubblico `/share`; la radice
del portale non risultava bloccata. RC7 sposta pertanto i link generati su
`/guest-access` e rimuove la route Guest `/share`. I link emessi dalle versioni
precedenti devono essere revocati e ricreati dopo l'aggiornamento.

Pubblicazione RC7: commit `a1410dc`, tag/release `v0.1.0-rc7`. Qualifica locale:
14 test PASS e compileall PASS. GitHub Actions tag `42839890816`: test,
metadati e build Docker amd64 PASS. Aggiornamento Hassio e verifica browser
reale del nuovo percorso restano al proprietario; nessuna installazione o
comando reale eseguiti dall'agente.

## Handoff precedente - RC4 installata e avviata (10/11/2026)

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
## Handoff corrente - RC19 pubblicata, link stabili fino alla revoca (10/11/2026)

Pubblicata e qualificata RC19. Le revisioni dovute a modifica permessi,
salvataggio cumulativo o rimozione di schede non invalidano piu link e sessioni
Guest: i nuovi permessi diventano effettivi immediatamente sul medesimo
accesso. Un link permanente termina soltanto con revoca amministrativa; un link
temporaneo termina con revoca oppure alla scadenza configurata. La
disattivazione esplicita dell'intero profilo resta fail-closed e revoca le
sessioni, mentre la revoca del link conserva motivazione e autore.

Commit `2877ea2`, tag/release `v0.1.0-rc19`. Qualifica locale: 16 test,
compileall, sintassi JavaScript admin/guest e diff-check PASS. GitHub Actions
tag `42866370485`: test, metadati e build `amd64`, `aarch64`, `armv7`, `armhf`
e `i386` PASS. Nessun accesso a impianti o installazione eseguito;
aggiornamento e collaudo restano al proprietario.
## Handoff corrente - RC22 pubblicata, dashboard Guest ottimizzata (10/11/2026)

Pubblicata e qualificata RC22. Il caricamento Guest usa una sola richiesta bulk
degli stati Home Assistant invece di una richiesta per entita; ogni refresh
scrive un solo evento audit di visualizzazione, mentre i comandi restano
registrati singolarmente con dispositivo, valore ed esito. Rimossi i refresh
sovrapposti. Aggiunti pulsante `Aggiorna` e opzione add-on
`polling_seconds`, configurabile da 15 a 3600 secondi con default 60. RC20 aveva
inoltre aggiunto favicon e Apple Touch icon alle due superfici.

Commit RC22 `c67bddb`, tag/release `v0.1.0-rc22`; 17 test, compileall,
sintassi JavaScript e diff-check locali PASS. GitHub Actions tag `42868920169`:
test, metadati e build `amd64`, `aarch64`, `armv7`, `armhf`, `i386` PASS.
Installazione e verifica del recupero CPU/assenza 524 restano al proprietario.
