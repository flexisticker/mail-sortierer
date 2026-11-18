# Postwart

*(früher „Mail-Sortierer“ – Repository, Image und Windows-Ordner heißen technisch weiter so.)*

Sortiert das IMAP-Postfach mit einer **lokalen KI (Ollama)** in Ordner und lernt aus deinen Korrekturen.
Kein Mailinhalt verlässt dein Netz. **Es wird nichts gelöscht** – nur verschoben (außer du schaltest das Aufräumen von Spam/Verdacht ein).

## Was er macht

- Schaut alle paar Minuten in den Posteingang (neueste Mails zuerst, Altbestand nach und nach, nachts mehr).
- Liest je Mail nur Absender, Betreff, ein paar Kopfzeilen und den Anfang des Textes (Anhänge nicht).
- Ordnet ein: **eigene Adresse → feste Regel → bekannter Kunde → lokale KI**.
- Verschiebt nach `Sortiert/Kunden`, `Lieferanten`, `Rechnungen und Zahlungen`, `Versand und Shop`,
  `System-Meldungen`, `Newsletter und Werbung`, `Ausmisten`. Unsicheres bleibt im Posteingang.
- **Probelauf** (Start): zeigt nur, was er tun würde. Erst nach „Scharf schalten“ wird verschoben.
- **Lernt mit:** Ziehst du in Outlook eine Mail in einen anderen Sortiert-Ordner oder zurück in den Posteingang,
  merkt er sich das beim nächsten Durchlauf (Beispiel für die KI + Absender-Regel, ab 2 gleichen Korrekturen fest).
  Dasselbe gilt für „Richtig wäre …“ in der Oberfläche.

## Rechnungen (ab 1.1)

- Mehrere Postfächer (Einstellungen → Postfächer), jedes mit eigenem Probelauf/Scharf.
- Rechnungen aus allen Postfächern landen im **Sammel-Postfach** (z. B. rechnung@flexisticker.de) unter
  `Rechnungen/JJJJ/JJJJ-MM` (Monat = Rechnungsdatum), mit Fähnchen in Outlook. Aus anderen Postfächern als Kopie,
  das Original kommt dort nach `Sortiert/Rechnungen und Zahlungen`.
- E-Rechnungen (ZUGFeRD/Factur-X, XRechnung) werden exakt aus der XML gelesen, sonst liest die lokale KI das PDF.
- Doppelte (gleiche Nummer + Betrag oder gleiche Datei) werden nur einmal abgelegt.
- **Scanner:** PDFs in die Unraid-Freigabe `scan` (Container `/scan`) – sie werden als Mail mit PDF in den Monatsordner gelegt
  und nach `erledigt/JJJJ-MM` verschoben.
- Seite **Rechnungen:** „Zur Buchhaltung“ (Lexware Office, „Belege zu prüfen“), „Privat“ (`Rechnungen/Privat/JJJJ`),
  „Keine Rechnung“. Entscheidungen werden je Lieferant gemerkt und vorgeschlagen.

## Sicherheit (ab 1.2)

- Jede Mail wird **vor** der Einordnung geprüft – Anhänge werden dabei nie geöffnet, nur als Bytes untersucht:
  ausführbare/getarnte Anhänge (`.pdf.exe`, Programmdatei als PDF), Makros (`.docm`, `vbaProject.bin` in `.docx`), HTML-Anhänge,
  Archive mit gefährlichem Inhalt oder Passwort, PDFs mit JavaScript/Launch/versteckten Dateien.
- Phishing-Merkmale: SPF/DKIM/DMARC fehlgeschlagen, Anzeigename einer Marke mit fremder Domain, nachgemachte Domains
  (`paypa1.com`, `dhI-paket.de`, `xn--…`), Links mit anderem Ziel als angezeigt, IP-Links, Kurz-Links, Druck + Passwortabfrage,
  dazu die Einschätzung der lokalen KI. Punktzahl ≥ Schwelle → Ordner **„Achtung Verdacht“**.
- **Spam:** Spam-Kennzeichnung des Mailservers und Sperrlisten (Spamhaus ZEN/DBL, SpamCop, SURBL per DNS – es gehen nur
  IP-Adresse/Domain an den Betreiber, nie Inhalte) → Ordner **„Spam“**.
- Auftragsbestätigungen werden erkannt und ohne Prüfung unter `Rechnungen/Auftragsbestätigungen/JJJJ` abgelegt; Rechnungen ohne Beleg landen unter „Ohne Beleg“.
- Optional aufräumen: Spam/Verdacht nach X Tagen in den Papierkorb oder endgültig löschen (Standard: nie), Mails mit Fähnchen bleiben.
- DNS-Server für die Sperrlisten einstellbar (Spamhaus lehnt öffentliche DNS-Server ab), mit Test-Knopf.
- Fehlalarm: „ist harmlos“ bzw. Mail in Outlook herausziehen → Absender gilt als vertrauenswürdig.
- Eigene Ordner mit Beschreibung für die KI (Einstellungen → Ordner).
- Rechnungen: Firma/privat aus der Anschrift („Michael Zatti – Flexisticker“, „… – 3dbymicha“), sonst KI nach Inhalt,
  im Zweifel **„Bitte prüfen“**. Ansicht nach Monat mit Lieferant, „Worum geht’s“, Betrag; **„Ab zu Lexware“** nur auf Klick.

## Mehrere Nutzer, Webmail, Zugriff von außen (ab 2.0)

- **Mehrere Nutzer** (z. B. Familie): Verwaltung → Nutzer. Jeder hat eine eigene Oberfläche und eigene Daten (eigene Datenbank unter
  `DATA_DIR/nutzer/<id>/`), die KI (Ollama) teilen sich alle über eine Warteschlange. Der Verwalter sieht keine fremden Mails, setzt aber
  Passwort und Zwei-Faktor zurück, meldet Geräte ab, sperrt. Bereiche (Rechnungen, Lexware, Scanner, Aufräumen, Ordner, Webmail) je Nutzer freigeben.
- **Zwei-Faktor-Pflicht** (Authenticator-App + 10 Notfallcodes), „Angemeldet bleiben“ 30 Tage.
- **Sortieren je Nutzer:** nur gelesene Mails einsortieren (ungelesene werden trotzdem sofort geprüft), gefährliche Mails nur markieren
  (Fähnchen + Schlagwort „Phishing“) oder verschieben.
- **Webmail** („Postfach“): Ordner, Liste, Suche, Lesen (bereinigt und abgeschottet, externe Bilder erst auf Klick, gefährliche Anhänge gesperrt),
  Markieren, Verschieben, Spam, Papierkorb; Schreiben mit HTML-Editor, Antworten/Allen/Weiterleiten, Anhänge, Entwürfe, Signaturen mit Logo.
- **Von außen** über Nginx Proxy Manager: siehe `docs/ZUGRIFF-VON-AUSSEN.md`. Angriffsschutz mit Fallen und IP-Sperren, Sicherheits-Check,
  wöchentliche Sicherheitsprüfung in der GitHub Action (npm audit, Trivy, gitleaks).

## Mail-Programm im Browser (ab 2.2)

- Nach der Anmeldung öffnet sich das **Mail-Programm**: am PC drei Spalten (Postfächer/Ordner · Liste · Mail),
  ein Klick öffnet die Mail rechts ohne Neuladen, ↑/↓ wechselt die Mail, nach Löschen/Verschieben öffnet sich die nächste.
  Am Handy und Tablet hochkant nacheinander (Liste → Mail → Zurück). Verdächtige Mails tragen ein rotes **!**.
- Oben nur noch **Mail · Rechnungen · Verwaltung**. In der Verwaltung: Übersicht, Sortierung, Gelernt, Protokoll, Einstellungen,
  Signaturen und (nur Verwalter) System (Nutzer, KI, Angriffsschutz, Sicherheits-Check).
- Freigabe **„Sortierung sehen und prüfen“** je Nutzer (Verwalter immer): ohne sie sieht man nur Mail und die eigenen Einstellungen,
  sortiert wird trotzdem im Hintergrund (Probelauf/Scharf je Postfach unter Einstellungen → Postfächer).
- **Handy und Tablet** zeigen nur die Mails der letzten 14 Tage (Einstellungen → Mail-Programm, 0 = alle), „Ältere anzeigen“ und die Suche gehen über alles.
  Auf dem Gerät wird nichts gespeichert – geladen werden nur die angezeigte Liste und die geöffnete Mail.

## Darstellung (ab 2.4)

- Knopf oben rechts: **automatisch · hell · dunkel** (je Gerät gemerkt).
- Einstellungen in Bereiche geteilt (Allgemein, Postfächer, Sortieren, Ordner, Rechnungen, Sicherheit, Mein Konto), Ordner als aufklappbare Zeilen.

## Zwei-Faktor einrichten (Anleitung)

Schritt für Schritt für Nutzer, auch direkt am Handy mit Authy: [docs/ZWEI-FAKTOR.md](docs/ZWEI-FAKTOR.md). Dieselbe Anleitung steht auf der Einrichtungsseite.

## Windows (ab 1.5)

`Postwart-Setup-<Version>.exe` (Download über die Vedly-Zentrale bzw. Action-Artefakt): läuft als Windows-Dienst,
Browser `http://localhost:8110`, Scanner-Ordner im Setup wählbar, Daten unter `C:\ProgramData\Mail-Sortierer`.
Für die KI „Ollama für Windows“ installieren. Lizenz: Vedly-Lizenzschlüssel mit Modul „Postwart“ (in der Zentrale `mailsort`) (30 Tage Test).

## Einrichten auf Unraid

1. **Ollama** läuft schon. Modell laden (Konsole des Ollama-Containers):
   `ollama pull qwen2.5:7b` (GTX 1060 mit 6 GB) bzw. `ollama pull qwen2.5:3b` (3 GB).
2. Vorlage `unraid/mail-sortierer.xml` nach `/boot/config/plugins/dockerMan/templates-user/` kopieren
   (oder in Unraid „Add Container“ von Hand: Image `ghcr.io/flexisticker/mail-sortierer:latest`,
   Port 8110 → 8080, Pfad `/mnt/user/appdata/mail-sortierer` → `/data`, `/mnt/user/scan` → `/scan`).
   Der ghcr-Login auf dem Unraid-Stick (wie bei Vedly) gilt auch für dieses Image.
3. `http://192.168.1.10:8110/` öffnen → Konto anlegen.
4. **Einstellungen → Postfach**: Server, Benutzer, Passwort von Alfahosting (wie in Outlook) → „Speichern & testen“.
5. **Einstellungen → Lokale KI**: Adresse von Ollama, z. B. `http://192.168.1.10:11434` → „Speichern & testen“.
6. Optional **Gelernt → Bekannte Kontakte**: Kundenliste (CSV aus Vedly) einfügen.
7. Probelauf ein paar Tage laufen lassen, unter **Mails** korrigieren, dann in der **Übersicht** „Scharf schalten“.

Von außen nur über Nginx Proxy Manager mit HTTPS freigeben (Anleitung `docs/ZUGRIFF-VON-AUSSEN.md`).

## Updates

GitHub Action baut bei jedem Push `ghcr.io/flexisticker/mail-sortierer` (`:latest` = `main`).
In Unraid: Docker → „Check for Updates“ → „apply update“. Daten bleiben erhalten.

## Entwicklung

```
npm ci
DATA_DIR=./data PORT=8199 npm start
```

## Passwörter verschlüsselt (ab 2.1)

Postfach-, SMTP- und Lexware-Zugänge sowie die 2FA-Geheimnisse liegen nur **verschlüsselt** (AES-256-GCM) in der Datenbank.
Der Schlüssel liegt **getrennt** von den Daten:

- **Docker/Unraid:** Variable `POSTWART_SCHLUESSEL`. Wert in Postwart unter Verwaltung → Sicherheits-Check → „Schlüssel anzeigen“
  (nur aus dem Heimnetz), in Unraid als Variable eintragen, Container neu starten – die Schlüsseldatei im Datenordner wird dann gelöscht.
  **Variable nie ändern oder löschen** und den Wert getrennt von der Sicherung aufbewahren (Passwort-Manager/Papier).
- **Windows:** automatisch mit Windows-DPAPI (Rechner-Schlüssel), Datei `.schluessel.dpapi`.
- Ohne beides: Datei `.schluessel` im Datenordner (Sicherheits-Check warnt).
- Passt der Schlüssel nicht zu den gespeicherten Passwörtern, **startet Postwart nicht** (statt still Zugänge zu verlieren).
