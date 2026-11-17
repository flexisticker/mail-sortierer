# Mail-Sortierer

Sortiert das IMAP-Postfach mit einer **lokalen KI (Ollama)** in Ordner und lernt aus deinen Korrekturen.
Kein Mailinhalt verlässt dein Netz. **Es wird nie etwas gelöscht** – nur verschoben.

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
- Fehlalarm: „ist harmlos“ bzw. Mail in Outlook herausziehen → Absender gilt als vertrauenswürdig.
- Eigene Ordner mit Beschreibung für die KI (Einstellungen → Ordner).
- Rechnungen: Firma/privat aus der Anschrift („Michael Zatti – Flexisticker“, „… – 3dbymicha“), sonst KI nach Inhalt,
  im Zweifel **„Bitte prüfen“**. Ansicht nach Monat mit Lieferant, „Worum geht’s“, Betrag; **„Ab zu Lexware“** nur auf Klick.

## Windows (ab 1.5)

`Mail-Sortierer-Setup-<Version>.exe` (Download über die Vedly-Zentrale bzw. Action-Artefakt): läuft als Windows-Dienst,
Browser `http://localhost:8110`, Scanner-Ordner im Setup wählbar, Daten unter `C:\ProgramData\Mail-Sortierer`.
Für die KI „Ollama für Windows“ installieren. Lizenz: Vedly-Lizenzschlüssel mit Modul „Mail-Sortierer“ (30 Tage Test).

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

Die Oberfläche **nicht** über Nginx Proxy Manager nach außen freigeben – nur Heimnetz.

## Updates

GitHub Action baut bei jedem Push `ghcr.io/flexisticker/mail-sortierer` (`:latest` = `main`).
In Unraid: Docker → „Check for Updates“ → „apply update“. Daten bleiben erhalten.

## Entwicklung

```
npm ci
DATA_DIR=./data PORT=8199 npm start
```
