# Mail-Sortierer – Projektgedächtnis

Eigenes Projekt von Michael (Flexisticker), **getrennt von Vedly** (`flexisticker/flex-studio`). Kommunikation Deutsch, Du-Form.
**Keine Passwörter, Tokens oder Schlüssel in Code, Doku oder diese Datei.**

## Ziel & Entscheidungen (17.11.2026)

- Outlook-Postfach (Alfahosting, **IMAP**) aufräumen mit **lokaler KI** – Kundendaten dürfen das Haus nicht verlassen.
  Ollama läuft auf Michaels Unraid mit **GTX 1060** → Standardmodell `qwen2.5:7b` (3-GB-Karte: `qwen2.5:3b`).
- Nie löschen, nur verschieben; unsicher = bleibt im Posteingang. Start im **Probelauf**.
- Lernen aus Korrekturen (Outlook-Verschiebungen werden erkannt) – Modell wird nicht trainiert, sondern Regeln + Beispiele (Few-Shot).
- **Schritt 2 (geplant, nicht gebaut):** Eingangsrechnungen aus Mails + Scanner-Ordner (Unraid-Freigabe), lokale KI prüft
  „Rechnung? geschäftlich?“, E-Rechnungen (ZUGFeRD/XRechnung) exakt aus XML, Doppel-Erkennung (Mail + Scan),
  Freigabe-Liste → erst nach Klick **an Lexware Office** (`POST /v1/files`, type voucher → „Belege zu prüfen“),
  eigener Lexware-API-Schlüssel nur mit Rechten „Dateien/Belegbilder hochladen + lesen“. Original-Mail bleibt im Postfach.
  Später evtl. Verknüpfung mit dem Einkauf in Vedly.

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
