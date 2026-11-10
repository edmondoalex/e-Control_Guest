# e-Control Guest

Prima di qualsiasi attivita leggere integralmente `../AGENTS.md` ed eseguire
la procedura automatica Ekonex. Questo repository e proprietario esclusivamente
dell'add-on e-Control Guest.

Regole aggiuntive:

- considerare ogni client Guest non attendibile;
- negare per default ogni entita, servizio e azione non esplicitamente ammessi;
- non esporre mai token Supervisor, credenziali impianto, PIN o token di
  condivisione a log, API pubbliche o frontend;
- registrare in audit ogni tentativo significativo, consentito o negato, e il
  readback successivo ai comandi;
- non usare servizi generici dell'impianto: ogni comando deve attraversare il
  catalogo di azioni consentite;
- non eseguire comandi su un impianto reale durante test o qualifica;
- push, release, catalogo e installazione richiedono gate esplicito.
