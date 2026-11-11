# e-Control Guest — guida

Architetture supportate: `amd64`, `aarch64`, `armv7`, `armhf` e `i386`,
inclusi Home Assistant Green e i sistemi Home Assistant legacy supportati dal
Supervisor.

## Prima configurazione

1. Installa e avvia l'add-on.
2. Nella configurazione imposta `guest_base_url` con l'indirizzo HTTPS pubblico
   del portale Guest, senza slash finale, per esempio
   `https://guest.example.it`.
3. Pubblica la porta Guest `8100/tcp` attraverso un reverse proxy HTTPS. La
   porta amministrativa `8099` è riservata a Ingress e non va pubblicata.
4. In **Apri interfaccia Web** crea un profilo Guest.
5. Scegli la dashboard e carica le schede. Se la lettura automatica non è
   disponibile sulla versione Home Assistant installata, espandi il fallback
   JSON e incolla la configurazione Lovelace.
6. Importa una singola scheda oppure usa **Importa l'intera vista in ordine**.
   L'add-on crea snapshot sicuri: le modifiche future alla dashboard sorgente
   non entrano automaticamente nella condivisione.
7. Abilita singolarmente lettura e azioni, quindi salva i permessi.
8. Crea il link indicando PIN, validità e numero massimo di sessioni. Il token
   completo viene mostrato una volta sola.

I link generati dalla RC7 usano il percorso pubblico `/guest-access`. I link
creati dalle versioni precedenti con il percorso `/share` vanno revocati e
ricreati dopo l'aggiornamento.

Ogni modifica a schede o permessi incrementa la revisione del profilo e rende
inutilizzabili i link creati sulla revisione precedente. Crea un nuovo link dopo
aver verificato la configurazione.

## Schede e comandi supportati

Sono importabili le schede integrate `entities`, `entity`, `tile`, `thermostat`,
`button`, `gauge`, `sensor` e le intestazioni `heading`. Ordine e intestazioni
della vista vengono conservati; il portale usa una griglia densa e responsive.
I contenitori `grid`, `vertical-stack` e
`horizontal-stack` vengono attraversati per estrarre le schede figlie. Le
`custom:*` non vengono eseguite nel portale Guest.

Le entita `climate` mostrano stato, temperatura attuale e setpoint. La lettura
non abilita automaticamente i comandi: modifica del setpoint e modalita HVAC
restano permessi separati, disabilitati fino all'approvazione esplicita.

Azioni disponibili, sempre disabilitate all'importazione:

- luci: accensione, spegnimento, luminosità con intervallo;
- switch: accensione e spegnimento;
- clima: temperatura con intervallo e modalità HVAC in elenco chiuso;
- cover: apertura, chiusura, stop e posizione con intervallo;
- pulsanti: pressione.

Il portale chiama un broker tipizzato. Non esiste un'API Guest che accetti un
dominio o un servizio Home Assistant arbitrario.

## Opzioni

- `guest_port`: porta del portale Guest, predefinita `8100`;
- `guest_base_url`: URL HTTPS usato per generare i link;
- `allow_insecure_local_http`: consente cookie Guest senza flag `Secure` solo
  per prove temporanee sulla LAN; deve restare `false` in produzione;
- `session_minutes`: durata massima della sessione, da 5 a 240 minuti;
- `session_idle_minutes`: inattivita massima prima di liberare automaticamente
  lo slot, da 1 a 60 minuti (default 3); un heartbeat dedicato mantiene attiva
  la dashboard aperta anche con polling dati piu lento;
- `audit_retention_days`: riserva per la politica di conservazione; la RC non
  elimina automaticamente eventi;
- `trusted_proxy_cidrs`: proxy autorizzati a fornire `X-Forwarded-For`. Se il
  peer non appartiene a queste reti, l'header viene ignorato.

## Registro e revoca

Il pannello mostra gli eventi con esito. Il database conserva visite, letture,
login riusciti o negati, controlli sessione, comandi richiesti e stato letto
dopo il comando. PIN, cookie e token sono rimossi dai metadati di audit. La
verifica della catena segnala modifiche retroattive al registro.

Revocando un link vengono revocate anche tutte le sue sessioni. Disattivando un
profilo o cambiandone schede e permessi, le sessioni della revisione precedente
non superano più la validazione.

## HTTPS

In produzione i cookie Guest hanno il flag `Secure`. Un accesso diretto via
`http://IP:8100` non crea quindi una sessione utilizzabile. Configura un reverse
proxy HTTPS e inserisci il suo URL in `guest_base_url`.

## Backup

Database e chiavi risiedono in `/data` e rientrano nel backup dell'add-on. Le
chiavi sono necessarie per verificare la catena audit e le sessioni già emesse.
Non copiare singolarmente i database senza la directory `secrets` associata.
