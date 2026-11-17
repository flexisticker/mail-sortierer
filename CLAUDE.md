# Mail-Sortierer – Projektgedächtnis

Eigenes Projekt von Michael (Flexisticker), **getrennt von Vedly** (`flexisticker/flex-studio`). Kommunikation Deutsch, Du-Form.
**Keine Passwörter, Tokens oder Schlüssel in Code, Doku oder diese Datei.**

## Ziel & Entscheidungen (17.11.2026)

- Outlook-Postfach (Alfahosting, **IMAP**) aufräumen mit **lokaler KI** – Kundendaten dürfen das Haus nicht verlassen.
  Ollama läuft auf Michaels Unraid mit **GTX 1060** → Standardmodell `qwen2.5:7b` (3-GB-Karte: `qwen2.5:3b`).
- Nie löschen, nur verschieben; unsicher = bleibt im Posteingang. Start im **Probelauf**.
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
- Sicherheit: ein Konto, scrypt 2^16, Sitzung nur SHA-256, Cookie HttpOnly/SameSite=Strict, CSRF-Feld + Origin-Prüfung, 5 Fehlversuche → 15 Min.,
  IMAP-Passwort AES-256-GCM (`secrets.js`, Schlüssel `DATA_DIR/.schluessel`). Nur Heimnetz (kein HTTPS im Container).
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
