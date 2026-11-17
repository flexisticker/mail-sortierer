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

## Einrichten auf Unraid

1. **Ollama** läuft schon. Modell laden (Konsole des Ollama-Containers):
   `ollama pull qwen2.5:7b` (GTX 1060 mit 6 GB) bzw. `ollama pull qwen2.5:3b` (3 GB).
2. Vorlage `unraid/mail-sortierer.xml` nach `/boot/config/plugins/dockerMan/templates-user/` kopieren
   (oder in Unraid „Add Container“ von Hand: Image `ghcr.io/flexisticker/mail-sortierer:latest`,
   Port 8110 → 8080, Pfad `/mnt/user/appdata/mail-sortierer` → `/data`).
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
