## Handoff corrente - RC35 pubblicata e qualificata (12/11/2026)

CHANGE065 completata nel solo clone ownerisolato. Commit ec9bb06 e tag/release
v0.1.0-rc35 pubblicati. Run43235905869(main)/43235906560(tag) SUCCESS:
51 Python/6UI PASS, metadati e build amd64/aarch64/armv7/armhf/i386 PASS;
smoke audit runtime readonly/senza rete PASS su tutte5architetture. Release e
configversion35 rilette GitHub, non draft. Nessuna installazione/riavvio/accesso
o comando impianto eseguito. File runtime originale owner preservati.

Registro con IP/Paese nuovi eventi firmati e pagine server100righe, ricerca
globale/snapshotstabile/streaming HMAC/labeljoin. Colonne dopo Dettagli e prima
Esito, conteggi e navigazione accessibili, raceguard/errori. Vecchi eventi
immutati: IP/Paese precedenti non ricostruibili. Nessun lookupesterno, solo
socket/proxy espliciti e CFspecifictrust separato defaultvuoto; metadati Paese
non certificano identita o posizione reale. Sessioni/PWA/CSRF/permessi/retention
invariati; Uvicorn non riscrive peer prima dei gate. Test fixtures sintetiche,
nessun dato cliente nei file o Git, nessun test browser reale dichiarato.

Prossimo user: aggiorna Guest35 dalla propria UI. Per IP/Paese dietroCloudflare
autorizza nelle opzioni il solo connector controllato cloudflare_proxy_cidrs
(/32 o /128, mai tuttaLAN/reteAPP) e assicurati che CF-IPCountry sia fornito
da CloudflareManagedTransform. No configurazione reale automatica dell'agente.
Se manca fonte Paese resta non disponibile; peer non fidato non attesta origine
remota. Collaudo live e privacy/retention configurate restano al proprietario.
Coordinamento centrale CHANGE065/workorder/syncEManager aggiornato.

## Handoff precedente - RC35 implementata, qualifica pubblicazione da completare (12/11/2026)

CHANGE065 richiesta user: IP provenienza e Paese dopo Dettagli, pagine100 righe.
Implementata nel clone owner isolato change065-guest-audit-local, baseline6d781da;
originale non modificato nel runtime. Gate specifico user: pubblica Guest dopo
i test; nessuna installazione/riavvio/accesso live/comando dispositivo.

Origine nuovi eventi via context request-local, socket reale e header solo da
proxy espliciti; XFF destra/primo non fidato, CIDR0 non accettati. Cloudflare
IP/Paese solo cloudflare_proxy_cidrs dedicato defaultvuoto, headerIP validato,
ISO/Tor/ignoto distinti, nessun lookupesterno. Uvicorn proxy_headersFalse evita
riscrittura peer prima dei gate Ingress. IP metadato Paese approssimativo, non
identita o posizione certa. Dati legacy non retrocalcolati, catena non riscritta.

API soloIngress massimo100righe, ricerca globale anche oltre1000 e per label
legacy, snapshotseq evita salti da nuovi eventi; verifica integrita nello stesso
snapshot SQLite e streaming, senza caricare intera catena in RAM. Label join
evita una connessione per riga. UI7colonne/paginatore/conteggi/debounce/raceguard/
errore e cache065. Retention, sessioni, CSRF e permessi invariati.

51 testPython/6UI locali PASS, compileall/Node/JSON PASS; nuove regressioni prima
rosse poi verdi. CI estesa a testUI e smoke audit senza rete su5architetture.
Config candidata0.1.0-rc35; commit/push/tag/release/CI da eseguire, nessun esito
anticipato. Paese richiede configurazione esplicita connector e ManagedTransform
CloudflareCFIPCountry; nessuna impostazione reale cambiata. Coordinamento
CHANGE065/workorder/sync E-Manager. Non dichiarare installazione/collaudo reale.

## Handoff precedente - RC34 pubblicata e qualificata (11/11/2026)

Pubblicato il ciclo sessione/PWA richiesto. Nuova opzione
`session_idle_minutes` default 3: le sessioni oltre soglia vengono revocate e
non contano nel limite; heartbeat autenticato ogni minuto, separato dal polling
dati, mantiene la dashboard realmente aperta. La durata assoluta
`session_minutes` resta invariata.

Il primo login valido crea una credenziale dispositivo opaca: cookie Secure,
HttpOnly, SameSite=Strict e solo digest nel nuovo archivio `device_grants`. La
PWA avviata senza frammento puo risolvere la share associata e richiede di nuovo
il PIN; token Guest assente da manifest, URL PWA e storage JavaScript. Revoca
share invalida sessioni e grant; logout chiude la sessione ma conserva
l'associazione del dispositivo.

File: `config.json`, `app/settings.py`, `app/runtime.py`, `app/storage.py`,
`app/guest_api.py`, `app/static/guest.js`, `tests/test_security.py`, `DOCS.md`.
Verifiche locali: 27 test PASS, compileall, node --check, JSON e diff-check
PASS. Commit `7efddbd`, tag e release `v0.1.0-rc34`; GitHub Actions
`43006837215` (main) e `43006839956` (tag) PASS con build `amd64`, `aarch64`,
`armv7`, `armhf` e `i386`. Catalogo, installazione e accesso impianto non
eseguiti; il prossimo gate e l'aggiornamento esplicito su Home Assistant.

## Handoff corrente - RC33 pubblicata, metadati PWA Chrome (10/11/2026)

Aggiunto `mobile-web-app-capable=yes` accanto al metadato Apple per eliminare
l'avviso di deprecazione Chrome. L'avviso relativo a `beforeinstallprompt` e
atteso: il banner automatico viene intercettato e mostrato soltanto dopo il
gesto esplicito sul pulsante `Installa app`, come richiesto dal browser.
Commit `c0ac09c`, tag `v0.1.0-rc33`; 26 test locali PASS. GitHub Actions
`42894647414` (main) e `42894653768` (tag): test, metadati e build `amd64`,
`aarch64`, `armv7`, `armhf`, `i386` PASS. Installazione non eseguita.

## Handoff corrente - RC32 pubblicata, gestione sessioni attive (10/11/2026)

Pubblicata e qualificata RC32. L'elenco link mostra le sessioni attive rispetto al
limite e consente all'amministratore di chiuderle senza revocare o modificare
il link. Questo risolve il caso in cui una scheda chiusa sul cellulare lasci lo
slot occupato fino alla scadenza. Il rientro dallo stesso browser recupera
inoltre il proprio slot tramite la sessione firmata anche se il cookie
dispositivo non e piu disponibile; non puo sostituire sessioni di altri
dispositivi. Tutte le chiusure amministrative sono registrate in audit.

26 test, compileall, sintassi JavaScript e diff-check locali PASS. Commit
`82298dd`, tag `v0.1.0-rc32`. GitHub Actions `42893370326` (main) e
`42893377288` (tag): test, metadati e build `amd64`, `aarch64`, `armv7`,
`armhf`, `i386` PASS. Installazione e collaudo Green non eseguiti.

## Handoff corrente - RC31 PWA, gestione link, JSON e audit limitato (10/11/2026)

Pubblicata e qualificata RC31. La sezione contenuti e permessi parte chiusa;
le condivisioni attive consentono di modificare durata e sessioni senza cambiare
token o PIN. Aggiunti installazione PWA senza cache di dati Guest/API, filtro e
limiti configurabili del registro audit, potatura con ancora HMAC verificabile,
oltre a esportazione e importazione JSON atomica di contenuti e permessi. Token,
PIN, sessioni e audit non sono inclusi nell'esportazione.

Commit `488f7f9`, tag `v0.1.0-rc31`; 24 test, compileall, sintassi JavaScript,
validazione JSON e diff-check locali PASS. GitHub Actions `42891127033` (main)
e `42891133198` (tag): test, metadati e build `amd64`, `aarch64`, `armv7`,
`armhf`, `i386` PASS. Installazione e collaudo sull'Home Assistant Green non
eseguiti e restano al proprietario.

## Handoff corrente - RC30 motivazioni login esplicite (10/11/2026)

Pubblicata e qualificata RC30. Il portale distingue PIN errato, limite di
sessioni simultanee, link scaduto/revocato/non valido, profilo disattivato e
diniego inatteso, mostrando una spiegazione operativa direttamente sotto il
form. Include il logo trasparente e il riutilizzo dello slot dello stesso
browser introdotti nella RC29.

Commit `f41185e`, tag/release `v0.1.0-rc30`; 21 test, compileall, sintassi
JavaScript e diff-check locali PASS. GitHub Actions tag `42879476901`: test,
metadati e build `amd64`, `aarch64`, `armv7`, `armhf`, `i386` PASS.
Installazione e verifica browser reale restano al proprietario.

## Handoff corrente - RC29 logo trasparente e rientro browser (10/11/2026)

Pubblicata e qualificata RC29. L'asset Ekonex di intestazione e splash usa un
PNG con vero canale alfa e nessun rettangolo nero incorporato. Corretto inoltre
il falso `session_limit`: il login riutilizza il cookie dispositivo esistente
e sostituisce la precedente sessione dello stesso browser; dispositivi diversi
continuano a rispettare il limite di simultaneita configurato.

Commit `402f739`, tag/release `v0.1.0-rc29`; 21 test, compileall, sintassi
JavaScript e diff-check locali PASS. GitHub Actions tag `42878359956`: test,
metadati e build `amd64`, `aarch64`, `armv7`, `armhf`, `i386` PASS.
Installazione e verifica browser reale restano al proprietario.

## Handoff corrente - RC27 recupero link legacy (10/11/2026)

Pubblicata e qualificata RC27. Corretto HTTP 500 dei pulsanti `Mostra link` e
`Copia link`: una condivisione attiva creata prima di RC23 riceve al primo
recupero un alias deterministico autenticato, mentre il link originale resta
valido. Entrambi cessano di funzionare soltanto a scadenza o revoca. I pulsanti
di recupero sono disabilitati per condivisioni scadute o revocate.

Commit `8caf9da`, tag/release `v0.1.0-rc27`; 20 test, compileall, sintassi
JavaScript e diff-check locali PASS. GitHub Actions tag `42876349300`: test,
metadati e build `amd64`, `aarch64`, `armv7`, `armhf`, `i386` PASS.
Installazione e verifica sul Green restano al proprietario.

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
## Handoff corrente - PWA, JSON e audit limitato, delta locale (10/11/2026)

Su richiesta del proprietario, la sezione amministrativa `3. Contenuto e
permessi` e ora chiusa per impostazione predefinita e si espande cliccando sul
titolo. Le singole schede interne conservano il proprio collasso indipendente.
I link attivi offrono inoltre la modifica in corso dei minuti residui, della
modalita senza scadenza e del massimo di sessioni simultanee, senza cambiare
token o PIN. Una riduzione del limite conserva le sessioni piu recenti e revoca
subito quelle eccedenti; una scadenza accorciata limita immediatamente anche le
sessioni aperte. Ogni modifica viene registrata nell'audit amministrativo.

File prodotto interessati: `app/admin_api.py`, `app/storage.py`,
`app/static/admin.html`, `admin-layout.css` e `admin.js`, con test di
regressione API/UI/storage.

Il portale Guest e ora predisposto come PWA installabile: manifest standalone,
icone reali 192/512, service worker network-only e pulsante installazione. API,
token, PIN e dati Home Assistant non vengono messi in cache. La sezione
contenuto permette inoltre export e import JSON di sole schede e permessi;
token, PIN, sessioni e audit sono esclusi. L'import sostituisce atomicamente le
schede del profilo, conserva i link e rifiuta tipi custom, entita, azioni o
permessi non validi.

Il Registro completo dispone di filtro client sugli ultimi 1000 eventi e
mostra conteggio, dimensione, retention e tetto massimo. Corretto il testo
`undefined dispositivi`. La retention configurata e ora realmente applicata;
aggiunta opzione `audit_max_events` default 100000. La potatura giornaliera usa
un anchor HMAC firmato, tronca WAL e compatta SQLite senza interrompere la
catena verificabile.

Verifiche finali: 24 test PASS, compileall, `node --check` su admin/Guest/service
worker, validazione manifest/config JSON e `git diff --check` PASS. Delta solo
locale sulla base RC30: nessun incremento versione, commit, push, release,
catalogo, installazione o comando reale.
