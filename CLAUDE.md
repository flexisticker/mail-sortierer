# Mail-Sortierer – Projektgedächtnis

Eigenes Projekt von Michael (Flexisticker), **getrennt von Vedly** (`flexisticker/flex-studio`). Kommunikation Deutsch, Du-Form.
**Keine Passwörter, Tokens oder Schlüssel in Code, Doku oder diese Datei.**

## Ziel & Entscheidungen (17.11.2026)

- Outlook-Postfach (Alfahosting, **IMAP**) aufräumen mit **lokaler KI** – Kundendaten dürfen das Haus nicht verlassen.
  Ollama läuft auf Michaels Unraid mit **GTX 1060** → Standardmodell `qwen2.5:7b` (3-GB-Karte: `qwen2.5:3b`).
- Nie löschen, nur verschieben (Ausnahme seit 1.7.0: Aufräumen von Spam/Verdacht, nur wenn eingestellt); unsicher = bleibt im Posteingang. Start im **Probelauf**.
- Lernen aus Korrekturen (Outlook-Verschiebungen werden erkannt) – Modell wird nicht trainiert, sondern Regeln + Beispiele (Few-Shot).
- **Schritt 2 = gebaut in 1.1.0** (Details unten unter Stand). Ursprünglicher Plan: Eingangsrechnungen aus Mails + Scanner-Ordner (Unraid-Freigabe), lokale KI prüft
  „Rechnung? geschäftlich?“, E-Rechnungen (ZUGFeRD/XRechnung) exakt aus XML, Doppel-Erkennung (Mail + Scan),
  Freigabe-Liste → erst nach Klick **an Lexware Office** (`POST /v1/files`, type voucher → „Belege zu prüfen“),
  eigener Lexware-API-Schlüssel nur mit Rechten „Dateien/Belegbilder hochladen + lesen“. Original-Mail bleibt im Postfach.
  **Vedly-Anbindung (Schritt C, besprochen, nicht gebaut):** Kontakte automatisch aus Vedly, Lieferantenrechnung erscheint im Vedly-Einkauf
  bei der passenden Bestellung (Betrag/Wareneingang prüfen), „Zur Buchhaltung“ dann über Vedlys Lexware-Anbindung. Sortierer bleibt der Eingang.

## Architektur

- Node 22 (ESM), Express 5, `node:sqlite`, `imapflow`, `mailparser`. Oberfläche serverseitig (kein Framework), `public/app.js` ohne Inline-Skripte (CSP).
- `src/db.js` Tabellen: kv, users, sessions, **mails** (Schlüssel Message-ID; status planned|moved|kept|undone|error|gone, folder/uid/uidvalidity = wo zuletzt gesehen),
  **rules** (sender|domain → target, state suggest|active|off, hits, conflicts, origin outlook|ui|hand|gemischt), **examples**, **contacts**, log.
- `src/config.js`: Vorgaben, Kategorien mit **festen IDs** (kunden, lieferanten, rechnungen, versand, system, newsletter, ausmisten) + 'inbox'.
  Ordnernamen ohne `/ \ . & ? …` (`cleanFolderName`). Pfade als Array → imapflow setzt Trennzeichen/Namensraum (z. B. `INBOX.`).
- `src/worker.js` Durchlauf: (1) `watchFolders` – neue UIDs in Sortiert-Ordnern > lastUid (kv `watch`): bekannte Mail mit anderem Ziel = Korrektur,
  unbekannte = von Hand einsortiert (Beispiel). Erstes Mal nur Ausgangsstand. (2) `processInbox` – unbekannte UIDs, neueste zuerst, Batch Tag/Nacht;
  bekannte Message-ID, die vorher verschoben war und jetzt im Posteingang liegt = Korrektur „inbox“. (3) scharf: vorgemerkte verschieben.
  Ollama-Fehler brechen den Durchlauf ab (nächster Lauf holt nach). Max. 15 Min. je Lauf.
- `src/learn.js`: `learnSender` (1. Korrektur = Vorschlag, ab `ruleAfter` gleich = gilt, 2. Widerspruch = aus/gemischt; von Hand angelegte bleiben),
  `examplesFor` (gleicher Absender › Domain (nicht Freemail) › Wortüberlappung), Domain-Regeln gelten auch für Subdomains.
- `src/classify.js`: eigene Adresse → aktive Regel → Kontakt Kunde (fest) / Lieferant (Hinweis) → Ollama `/api/chat` mit JSON-Schema, temperature 0,
  Beispiele als user/assistant-Paare. Unter `minConfidence` (Ausmisten `minConfidenceTrash`) → Posteingang mit Vorschlag im Grund.
- Sicherheit (ab 2.0): mehrere Nutzer, scrypt 2^16, Sitzung nur SHA-256, Cookie HttpOnly/SameSite=Lax (+Secure über HTTPS), CSRF-Feld + Origin-Prüfung,
  5 Fehlversuche → 15 Min., **TOTP-Pflicht**, IMAP-/SMTP-Passwörter + 2FA-Geheimnis AES-256-GCM (`secrets.js`, Schlüssel `DATA_DIR/.schluessel`).
  Von außen über NPM (HTTPS dort), `trust proxy` = loopback + uniquelocal, Angriffsschutz `shield-core.js` (Kopie aus Vedly).
- Zweige wie bei Vedly: Entwicklung `claude/…`, **`main` = Produktivstand (`:latest`)** – jede Auslieferung auch nach `main` pushen.
  Paket auf ghcr.io ist **öffentlich** (Unraid hat für neue Pakete keine gültige Anmeldung).
- Docker: `ghcr.io/flexisticker/mail-sortierer`, Action `.github/workflows/docker.yml` (gitleaks + npm audit vor dem Build). Unraid-Vorlage `unraid/`, Host-Port 8110.

## Testen

- IMAP: GreenMail standalone (Maven Central `com.icegreen:greenmail-standalone`), `-Dgreenmail.setup.test.smtp -Dgreenmail.setup.test.imap
  -Dgreenmail.users=michael:geheim@flexisticker.test -Dgreenmail.users.login=email` (IMAP 3143 ohne TLS, Trennzeichen „.“, belegt Port 8080!).
- Ollama: kleiner Mock (Stichwörter → Kategorie, folgt Beispielen mit gleichem Absender). Server: `DATA_DIR=<tmp> PORT=8199 node src/index.js`.
- Alle POSTs brauchen das `csrf`-Feld aus einer Seite + Cookie.

## Stand

- **1.0.0 (17.11.2026):** Probelauf/scharf, Ordner anlegen + abonnieren, Korrekturen aus Outlook (anderer Ordner, zurück in den Posteingang,
  von Hand einsortiert), „Richtig wäre“/„passt“/Rückgängig in der Oberfläche, Regeln (auch von Hand, Domain), Kontaktliste (CSV/Liste),
  Einstellungen mit IMAP-/KI-Test, Protokoll, Handy-Ansicht. Getestet gegen GreenMail + Ollama-Mock (Playwright 1280/390 px, hell/dunkel).
  **Nicht getestet:** echtes Alfahosting-IMAP (Namensraum `INBOX.`?), echtes Ollama/GTX 1060 (Laufzeit, Qualität der Einordnung), großes Postfach.
- **1.1.0 (17.11.2026):** Mehrere Postfächer (Tabelle `accounts`, Passwort `imap:<id>`, `mode` probe|live je Postfach; Umzug von 1.0:
  `migrateAccounts` macht aus `config.imap` Postfach 1, `mails` bekommt `account_id`, UNIQUE(account_id, msgid); kv `watch`/`inboxBaseline` je Postfach).
  **Rechnungen** (`src/invoice.js`, Tabelle `invoices`): Sammel-Postfach `config.invoices.accountId` (Michael: rechnung@flexisticker.de),
  Ablage `Rechnungen/JJJJ/JJJJ-MM` nach Rechnungsdatum, `\Flagged` = offen. Mail im Sammel-Postfach wird selbst verschoben (`same_message`),
  aus anderen Postfächern APPEND der ganzen Mail (Original → Sortiert/Rechnungen). Auslesen: XML-Anhang bzw. in PDF eingebettete XML
  (`embeddedXml`, FlateDecode-Streams) → `parseEInvoice` (CII + UBL), sonst `unpdf`-Text + KI (`kiExtract`, JSON-Schema mit privat/geschäftlich).
  Doppelt: `file_hash` oder `dedupeKey` (Nummer + Betrag). Belege als Datei unter `DATA_DIR/belege/JJJJ/`. Scanner: `config.invoices.scanDir`
  (`/scan`), nur wenn Sammel-Postfach scharf, Datei älter als 60 s, Mail mit PDF wird per APPEND angelegt (`buildScanMail`), Datei → `erledigt/JJJJ-MM|doppelt|fehler`.
  Aktionen: Lexware `POST /v1/files` (multipart, `type=voucher`, max. 5 MB, Schlüssel `lexwareKey`), Privat → `Rechnungen/Privat/JJJJ`,
  Keine Rechnung → `Rechnungen/Keine Rechnung`, Wieder öffnen, Angaben ändern (anderer Monat = Mail wandert mit). Entscheidungen je Lieferant kv `invoiceDecisions`.
  Unraid-Port **8110** (8099/8100 belegt), Pfad `/mnt/user/scan` → `/scan`, Symbol `/icon.png`.
  Getestet: GreenMail mit 2 Postfächern, PDF/ZUGFeRD (pdf-lib attach)/XRechnung-XML/CC-Doppel/Scan, Lexware-Nachbau, Umzug einer 1.0-Datenbank, 1280/390 px.
  **Nicht getestet:** echtes Lexware (`/v1/files` mit XML-Datei?), echte Scanner-PDFs ohne Textebene (dann Angaben von Hand), echte ZUGFeRD-PDFs
  mit Objektströmen (Einbettung evtl. nicht gefunden → KI liest PDF-Text).
- **1.1.1:** Liste springt nach Korrektur nicht mehr nach oben (Anker = Zeile davor, `anker`-Feld, `withAnchor`).
- **1.2.0 (17.11.2026):** Wünsche Michael: eigene Ordner, Firma/privat bei Rechnungen, Schutz vor bösen Mails, Phishing-Erkennung, Spam-Sperrlisten,
  Rechnungen nach Monat mit „Worum geht’s“ und „Ab zu Lexware“ (nie automatisch). Flexisticker + 3dbymicha laufen über **eine** Lexware-Buchhaltung.
  - Kategorien: feste + eigene (`c_<hex>`, Einstellungen → Ordner) + System `spam`, `verdacht` (nie von der KI gewählt, `kiCategories`).
  - `src/security.js`: `scanAttachment` (Endungen, Magic Bytes MZ/%PDF/OLE, ZIP-Verzeichnis lesen ohne Entpacken, verschlüsselte ZIPs, Makros),
    `pdfRisk` (/JavaScript, /Launch, /SubmitForm, /RichMedia, /XFA, eingebettete Dateien außer factur-x/zugferd/xrechnung; auch in Objektströmen),
    `phishCheck` (Punkte: DMARC 40, Lookalike 40, Marken-Anzeigename 35, Link-Text≠Ziel 30, IP-Link 30, Druck+Zugangsdaten 25, SPF 20 …;
    bekannte Absender −30, vertraute = 0 außer gefährliche Anhänge), `lookalike` (Levenshtein, Verwechsler 0/1/I/rn, Marke + Lockwort in Domain-Tokens),
    `blocklistCheck` (DNSBL parallel, 4 s, Fehlercodes 127.255.255.x = Abfrage gesperrt → Warnung). Marken-Liste `BRANDS` + Einstellung `security.brands`.
  - `worker.js assess()`: Prüfung vor Regeln/KI → `verdacht` (gefährlich oder ≥ `phishThreshold` 60) bzw. `spam`; KI-Feld `verdacht` ≥ 80 gibt +25.
    Spalten `mails.risk/risk_reasons`. Vertrauen: Regel-Art `trust` (`trustSender`), entsteht bei „ist harmlos“ oder Korrektur aus verdacht/spam heraus.
    `readMessages` liefert `_headers/_html/_text/_attachments` (nur im Speicher), Archive/Office bis 15 MB werden komplett geladen (nur Bytes).
  - Rechnungen: `detectCompany` (Firmen aus `invoices.companies`, Mail-/Web-Adressen werden vorher entfernt – sonst wäre rechnung@flexisticker.de immer „Flexisticker“),
    KI-Feld `zuordnung` firma|privat|unklar + `inhalt` → `suggestion` business|private|check, Spalten `brand`, `content`, `risk`, Status `blocked`
    (gefährlicher Beleg: Mail → verdacht, keine Ablage, „Trotzdem freigeben“ nur für Lexware, Vorschau bleibt 403). PDF-Text mit `isEvalSupported: false` + 20 s Zeitlimit.
    Seite Rechnungen: Gruppen je Monat (Summe, Aufteilung Firma/privat/zu prüfen), Monats-Knopf schickt nur geschäftliche mit Beleg (nicht ❓/privat), Rückfrage mit Liste.
  - Getestet (GreenMail + Mocks): PayPal-Phishing (220 P.), `.pdf.exe`, PDF mit JS (pdf-lib addJavaScript), ZIP mit `.js`, X-Spam-Flag, eigener Ordner,
    3dbymicha-Rechnung, „nur Michael Zatti“ → Prüfen, „ist harmlos“ → vertraut, echte DHL-Mail 0 Punkte, 1280/390 px.
    **Nicht getestet:** echte DNSBL-Abfragen (Sandbox ohne DNS; Spamhaus blockt öffentliche Resolver), echte Alfahosting-Header (Authentication-Results/X-Spam-*),
    echte Phishing-Mails, Ollama-Qualität bei „zuordnung“.
- **1.3.0 (17.11.2026):** Wunsch Michael: „bei allen Mails, die ich prüfe und ändere, soll die KI lernen“.
  Rechnungen: Tabelle `inv_examples` (+ Spalte `invoices.text_snippet`), `invLearn(inv, business|private|noinvoice|edit)` bei Lexware/Privat/Keine Rechnung
  und bei „Angaben ändern“ (wenn sich etwas ändert). kv `supplierAlias` (`m:<absender>`, `d:<domain>` ohne Freemail) → Lieferantenname + Firma bzw. privat
  werden bei neuen Belegen des Absenders übernommen (`aliasFor` in `analyze`), `kiExtract` bekommt bis zu 3 Beispiele desselben Absenders/der Domain.
  Scans haben keinen Absender → lernen nur über die Lieferanten-Entscheidung. Gelernt-Seite: Abschnitt „Rechnungen – gelernt“ mit „vergessen“.
  Mails: Knopf „Seite geprüft – alles passt (n)“ → `confirm()` für alle nicht geänderten Zeilen der Seite (Regel-Treffer + Beispiele).
  Getestet (GreenMail + Mocks): Korrektur FS-3001 → neue Rechnung FS-3002 mit nur „Michael Zatti“ kommt als „Filament Shop / 3dbymicha“, KI bekam 1 Beispiel.
- **1.4.0 (17.11.2026):** „Zu Lexware prüfen ab Jahr“ (`invoices.fromYear`, 0 = alle; Michael: **2025 ist erledigt → 2026 einstellen**).
  Ältere Jahre: weiter Ablage `Rechnungen/JJJJ/JJJJ-MM`, aber Status `archived` („Jahr abgeschlossen“), kein Fähnchen, kein Lexware-Knopf (`yearClosed`).
  Beim Speichern `applyYearSetting()`: offene älterer Jahre → archived (Fähnchen weg), archivierte aus nun geprüften Jahren → wieder offen.
  Datum in „Angaben ändern“ verschiebt den Status mit.
- **1.4.1:** Michael musste sich ständig neu anmelden – Ursache Cookie `SameSite=Strict` (kommt beim Aufruf über einen Link, z. B. Unraid „WebUI“, nicht mit).
  Jetzt `SameSite=Lax` (CSRF-Feld + Origin-Prüfung schützen weiter), Haken „Angemeldet bleiben (30 Tage)“ (Standard an; Spalte `sessions.remember`,
  ohne Haken 12 Std. gleitend + Sitzungs-Cookie), Cookie wird bei Nutzung erneuert (`renewed`).
- **1.5.0 (17.11.2026):** Mail-Sortierer wird **mit Vedly angeboten** (Michael: „mit in die Lizenzverwaltung“, „nichts vorausgefüllt“).
  - **Neutrale Vorgaben:** Ollama leer (Windows `http://localhost:11434`), Inhaber/Firmen/Betrieb leer, KI-Texte ohne Flexisticker (`bizText`, `business.name/description`),
    Abschnitt „Dein Betrieb“ in den Einstellungen (Name, Beschreibung, Inhaber, Firmen/Marken). Eigeninstallation: `index.js` setzt einmalig (kv `neutralDefaultsMigrated`)
    Michaels bisherige Werte, falls nie gespeichert.
  - **Lizenz** `src/license.js` (Port von Vedly `server/license.js`, nur online): `installId`, Bestand vor 1.5.0 = `licenseExempt` (Michael), sonst 30 Tage Test;
    Aktivierung mit Vedly-Schlüssel bei der Zentrale (`product: 'mailsort'`), Erneuerung 7 Tage, Lease; ohne Lizenz `licensedFull()` = false → alle Postfächer
    nur Probelauf, keine Scans, kein Lexware. Öffentlicher Schlüssel `src/license-keys.js` (gleich Vedly). Zentrale-Adresse kv `licenseServer` (Test), Standard lizenz.vedly.de.
    Gegenstück: **Vedly-Zentrale 1.8.0** (Repo flex-studio, Modul `mailsort`, Aktivierungen je Produkt, Download-Knopf).
  - **Windows:** `windows/build.ps1`, `windows/Mail-Sortierer.iss` (UTF-8 mit BOM!), `windows/test.ps1`, `notfall-zugang.cmd` → `src/reset-admin.js`.
    Dienst-ID `Mail-Sortierer` (WinSW), Programm `C:\Program Files\Mail-Sortierer`, Daten `C:\ProgramData\Mail-Sortierer` (nur SYSTEM + Admins), Port 8110,
    Setup-Seite „Scanner-Ordner“ (Aufgabe `scan`, Standard `C:\Scans`) → Umgebung `SCAN_DIR` (Vorgabe für `invoices.scanDir` + scanEnabled), Netzwerkfreigaben
    mit Benutzer/Passwort (`scanUser`, Geheimnis `scanPassword`, `net use` in `ensureShare`), Knopf „Speichern & Ordner prüfen“ (`checkScanDir`).
    Action-Jobs `windows` + `windows-publish` → `ghcr.io/flexisticker/mail-sortierer:windows` (main) bzw. `windows-<zweig>`.
- **1.5.1:** „Sicherheitsprüfung fehlgeschlagen“ beim Anmelden: Login-Formular wurde abgeschickt, während noch eine gültige Sitzung bestand
  (wiederhergestellter Tab, seit „Angemeldet bleiben“ häufig) → CSRF-Feld fehlte. `/anmelden` und `/einrichten` sind jetzt von der Sitzungs-CSRF-Prüfung
  ausgenommen (Origin-Prüfung bleibt); andere veraltete Formulare leiten mit Hinweis zur Seite zurück statt 403-Text.
- **1.6.0:** DNS-Server für die Sperrlisten einstellbar (`security.dnsServer`, leer = automatisch; IP, IP:Port, [IPv6]:Port, max. 3; eigener `dns.Resolver` in security.js),
  Anzeige des automatisch genutzten DNS (`dns.getServers()`), Knopf „Speichern & Sperrlisten testen“ (`testBlocklists`: offizielle Testeinträge 127.0.0.2,
  dbltest.com, surbl-org-permanent-test-point.com → funktioniert/gesperrt/keine Antwort). Hinweis: Spamhaus braucht einen selbst auflösenden DNS (Pi-hole+Unbound);
  die UDM leitet meist nur weiter. Getestet mit nachgebautem DNS-Server, **nicht** mit echtem Spamhaus (Sandbox ohne DNS).
- **1.7.0:** Wunsch Michael: Spam- und Verdacht-Mails löschen. `src/cleanup.js`: `config.cleanup {spam, verdacht (Tage, 0 = nie, Standard), mode trash|delete}`,
  nur scharfe Postfächer mit Lizenz, im Durchlauf nach `processInbox`. Frist zählt ab Erstsichtung im Ordner (kv `cleanupSeen[acc][pfad] {uv, first{uid: ms}}`),
  Mails mit Fähnchen bleiben, max. 500 je Ordner und Lauf. Papierkorb = Sonderordner `\Trash`, sonst Name (Trash/Papierkorb/Gelöschte Elemente …), keiner → Warnung, nichts passiert.
  „… jetzt leeren“ (Einstellungen → Sicherheit) = kv `cleanupNow` + `runOnce`. Datensätze `status 'deleted'` („Aufgeräumt“), Papierkorb-Fall mit `folder` = Papierkorb
  (dann geht „ist harmlos“/Korrektur noch, `correct()` sucht per Message-ID), endgültig = ohne folder. Getestet gegen GreenMail (Frist, Fähnchen, Papierkorb, endgültig, Datensatz), Einstellungen 1280/390.
- **1.7.1:** Wunsch Michael: Rechnungen ohne Beleg nicht prüfen. Status **`nodoc`** („Ohne Beleg“): Mail-Rechnung ohne PDF/XML wird weiter im Monatsordner abgelegt,
  aber ohne Fähnchen, nicht in „Offen“, nicht in Monatssummen, keine Knöpfe. `applyNoDoc()` (invoice.js, vor jedem Durchlauf) stellt bestehende offene/fehlerhafte
  Einträge ohne Datei um und nimmt das Fähnchen weg. Filter „Ohne Beleg (n)“ auf der Seite Rechnungen. Getestet: Umstellung + Seite (Datenbank-Test), Mail-Weg nicht gegen GreenMail.
- **1.8.0:** Wunsch Michael: Auftragsbestätigungen nicht prüfen, eigener Ordner. Status **`order`**, Ablage `Rechnungen/Auftragsbestätigungen/JJJJ`
  (`invoices.orderName`, Einstellungen → Rechnungen), ohne Fähnchen, nicht in „Offen“/Summen, keine Doppel-Sperre per Nummer+Betrag (`dedupe` null, findDuplicate ignoriert `order`).
  Erkennung `isOrderConfirmation()`: Betreff/Dateiname bzw. Anfang des PDF-Texts (`ORDER_RE`, nicht wenn „Rechnung/Invoice …“ dabei), sonst KI-Feld `belegart` (neu im Schema);
  E-Rechnungen nie. `applyOrders()` vor jedem Durchlauf sortiert bestehende offene Einträge per Stichwort um. Knopf „Auftragsbestätigung“ (`markOrder`, lernt als Beispiel `order`),
  „Wieder öffnen“ merkt die ID in kv `orderKeepOpen` (wird dann nicht wieder automatisch umsortiert). Getestet gegen GreenMail + Ollama-Mock (Betreff, nur KI, normale Rechnung).
- **2.0.0 (18.11.2026):** Wunsch Michael: Familie soll mitnutzen (eigene Oberfläche, gemeinsame KI), von außen erreichbar, 2FA-Pflicht, Fallen wie in Vedly,
  regelmäßige Sicherheitsprüfung, Webmail (lesen + schreiben, HTML-Editor, Signaturen), nur gelesene sortieren, gefährliche markieren, Funktionen je Nutzer abschaltbar.
  Entscheidungen (Vorschläge angenommen): Familie darf Ordner anlegen, gefährliche Mails bei Familie nur markieren, beliebig viele Nutzer, Verwalter sieht keine fremden Mails,
  Verwaltung von außen nur mit erneuter Code-Eingabe, KI/Angriffsschutz nur aus dem Heimnetz.
  - **Mehrnutzer** (`db.js`): `sysdb` = Haupt-Datenbank (users, sessions, kv für Lizenz/Angriffsschutz/`config.ollama`, `updateCheck`) **und** Daten des ersten Kontos (`users.data = ''`).
    Weitere Nutzer: `DATA_DIR/nutzer/<id>/daten.sqlite` + `belege/`. `withUser(user, fn)` setzt den Kontext (AsyncLocalStorage); **`db` ist ein Proxy** auf die DB des aktuellen Nutzers,
    `dataDir()` dessen Ordner, `sysGet/sysSet/sysLog` immer Haupt-DB. **Regel: keine `db.prepare` auf Modulebene** (bindet sonst an die falsche DB) – immer in Funktionen.
    Web: nach der Anmeldung `withUser(user, next)`; Worker: `startScheduler` läuft alle aktiven Nutzer nacheinander durch, `running` je Nutzer. Ollama: globale Warteschlange (`serial` in ollama.js).
    `getConfig()`: `ollama` immer aus sys-config (nur Verwalter darf speichern), `features` aus `users.features` (`featuresOf`, Bereiche invoices/lexware/scan/cleanup/folders/webmail;
    Verwalter alles, neue Nutzer `SIMPLE_FEATURES`), abgeschaltete Bereiche werden in getConfig erzwungen (accountId 0 usw.), saveConfig überschreibt die gespeicherten Werte dann nicht.
  - **Anmeldung** (`auth.js`, `totp.js`, `web-login.js`): Stufen `pw` → `enroll`/`mfa` → `full` (sessions.stage, 15 Min. bis full). TOTP RFC 6238 eigen (geprüft mit RFC-Testvektoren),
    `totp_last` gegen Wiederverwendung, 5 falsche Codes = Sitzung weg, Notfallcodes (10, SHA-256). Sitzungen ohne 2FA (Bestand) müssen beim nächsten Aufruf einrichten.
    Verwalter: `adminResetPassword` (Einmal-Passwort, must_change), `adminReset2fa`, `adminLogoutAll`, sperren, löschen (`dropUserData`). `reset-admin.js` setzt auch 2FA zurück.
  - **Verwaltung** (`web-admin.js`): `/verwaltung` (Nutzer), `/verwaltung/ki`, `/verwaltung/schutz`, `/verwaltung/check`; Zugang Verwalter + (Heimnetz `isHome` oder `stepupValid` 10 Min.,
    `/verwaltung/bestaetigen`); KI/Schutz ändern nur Heimnetz (`homeOnly`). Direkt nach der Anmeldung gilt die Bestätigung schon (stepup_at = Anmeldezeit).
  - **Angriffsschutz** (`shield-core.js` = Kopie aus Vedly, `shield.js`): Fallen + robots-Köder `/intern/sicherung`, unsichtbarer Link `/intern/kontakt`, Honeypot + Zeitstempel im Login (`loginTrap`,
    minMs 1200), Fehlanmeldung = Strafpunkt, nach Login `trust`. Zustand sys-kv `shield`, Einstellungen `shieldConfig` (keine Mails). `scripts/shield-check.mjs` (OK_PATHS bei neuen Seiten ergänzen!).
    Sicherheits-Check `selfCheck()` (Schutz, 2FA aller Nutzer, HTTPS/echte IP über `noteVisitor`, Update über `updates.js` = ghcr-Label `de.flexisticker.version` von `:latest`, Lizenz).
  - **Action**: wöchentlich Mo (schedule, baut nichts), Trivy auf node:22-slim (per Digest), Angriffsschutz-Prüfung im Job secrets; Build-Jobs `if: event != schedule`.
  - **Sortieren je Nutzer** (`config.sorting {onlySeen, danger move|mark}`): onlySeen → nur `\Seen` einsortieren, ungelesene einmal `securityCheck` (kv `unseenChecked`), gefährlich → `markDanger`
    (`\Flagged` + `$Phishing`). mark-Modus: Datensatz `kept` mit decision verdacht, „ist harmlos“ entfernt die Markierung.
  - **Webmail lesen** (`webmail.js`, `web-mail.js`): Verbindung je Nutzer+Postfach 3 Min. offen, Aufrufe nacheinander. `/post/:acc` Liste (50, Suche IMAP), `/lesen`, `/inhalt` (eigenes Dokument im
    `<iframe sandbox>` mit CSP sandbox, `img-src data:` bzw. + `https:` nach „Bilder laden“, cid-Bilder als data: eingesetzt, externe Bilder/CSS-url() ohne Freigabe entfernt – CSP allein reichte nicht),
    `/anhang` (gefährliche 403, nur PDF/Bilder inline), `.eml`, Aktionen (gelesen, Fähnchen, verschieben – Sortiert-Ordner lernt beim nächsten Durchlauf über watchFolders –, Spam, Papierkorb;
    ohne Papierkorb wird „Papierkorb“ angelegt). Bilder-Freigabe je Absender Tabelle `image_ok`. Seite `full` (ohne Breitenbegrenzung).
  - **Webmail schreiben** (`compose.js`, `web-compose.js`, `public/editor.js`): SMTP je Postfach (accounts.smtp_*, Passwort gleich IMAP oder `smtp:<id>`), nodemailer 10.6 mit `envelope + raw`
    (MailComposer, Bcc nur im Entwurf), data:-Bilder → cid-Anhänge (attachDataUrls wirkt bei MailComposer nicht!), `cleanOutgoing` (sanitize-html), `htmlToText`, Kopie in Gesendet (`\Sent` bzw. Name,
    sonst „Gesendet“ anlegen), `\Answered`/`$Forwarded`, Entwürfe (`\Draft`, alter Entwurf wird gelöscht). Formular multipart (busboy, 25 MB, 20 Dateien) – **CSRF dort in der Route**
    (`csrfLater`), multipart auf anderen Pfaden = 415. Editor: contenteditable + execCommand, Einfügen bereinigt, Bilder verkleinert (1600 px), Seiten mit Editor CSP `style-src 'unsafe-inline'`.
    Signaturen Tabelle `signatures`, Standard je Postfach `sig_new`/`sig_reply`, Wechsel im Editor über `<template id="sig-N">`.
  - Getestet: RFC-TOTP, Login-Ablauf mit 2FA/Einmal-Passwort/Reset (Playwright), Angriffsschutz (Falle → Sperre, Heimnetz nie), zwei Nutzer gegen GreenMail (getrennte Daten, onlySeen, markieren),
    Webmail gegen GreenMail (Skript/Formular entfernt, cid-Bild, Tracker erst nach Klick, .exe gesperrt, Löschen → Papierkorb), Senden über GreenMail-SMTP (Signatur mit Logo als cid, Anhang, Antwort mit
    In-Reply-To + \Answered, Weiterleiten mit Original-PDF, Entwurf → senden), Umzug einer 1.8-Datenbank (Daten, Ollama, Passwörter bleiben), von außen (Secure-Cookie, KI nur Heimnetz), 390 px.
    **Nicht getestet:** echtes Alfahosting (IMAP-Schlagwort `$Phishing`, SMTP 465), echtes Handy mit Authenticator-App, Weg über NPM, große Postfächer im Webmail, Outlook-Darstellung der gesendeten Mails.
