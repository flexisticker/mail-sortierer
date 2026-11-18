# Mail-Sortierer von außen erreichbar machen (Nginx Proxy Manager)

Ab Version 2.0 darf der Mail-Sortierer über das Internet erreichbar sein: Anmeldung mit Passwort **und** Code aus der
Authenticator-App (Pflicht für alle), Angriffsschutz mit Fallen und IP-Sperren, Verwaltung von außen nur nach erneuter Code-Eingabe.

## 1. DNS
Bei deinem Domain-Anbieter einen A-Eintrag anlegen, z. B. `mail.flexisticker.de` → deine feste IP (wie bei `studio.` und `freigabe.`).
Im Heimnetz (UniFi) zusätzlich einen lokalen DNS-Eintrag `mail` → IP des Nginx Proxy Managers, damit es auch zu Hause über den Proxy läuft.

## 2. Nginx Proxy Manager → Proxy Hosts → Add Proxy Host
- **Domain Names:** `mail.flexisticker.de`
- **Scheme:** `http`, **Forward Hostname/IP:** `192.168.1.10`, **Forward Port:** `8110`
- **Block Common Exploits:** an · **Websockets Support:** egal
- **SSL:** „Request a new SSL Certificate“, **Force SSL** an, **HTTP/2** an, **HSTS** an
- **Keine** Access-List „Nur Heimnetz“ (sonst kommt man von außen nicht hin)

Der Proxy reicht die echte Besucher-IP (`X-Forwarded-For`) und `https` (`X-Forwarded-Proto`) weiter – das ist bei NPM Standard.
Der Mail-Sortierer übernimmt diese Angaben nur von Proxys aus dem eigenen Netz.

## 3. Prüfen
- Mit dem Handy über Mobilfunk `https://mail.flexisticker.de` öffnen → Anmeldeseite.
- Verwaltung → **Sicherheits-Check**: „Zugriff von außen über HTTPS“ und „Echte Besucher-Adressen kommen an“ müssen grün sein.
- Verwaltung → **Angriffsschutz**: Nach einigen Stunden tauchen dort die ersten Bots auf – das ist normal.

## Was nur im Heimnetz geht
Gemeinsame KI (Ollama) und Einstellungen des Angriffsschutzes ändern. Nutzer verwalten (Passwort/2FA zurücksetzen, sperren …) geht
auch von unterwegs, aber nur nach erneuter Code-Eingabe (gilt 10 Minuten).

## Notfall
- Nutzer hat Passwort oder Handy verloren → Verwaltung → Nutzer → „Passwort zurücksetzen“ bzw. „2FA zurücksetzen“.
- Du selbst kommst nicht mehr rein → Unraid: Docker → Mail-Sortierer → Console:
  `node src/reset-admin.js` (zeigt Konten) und `node src/reset-admin.js <name>` (Einmal-Passwort, 2FA wird neu eingerichtet).
- Selbst ausgesperrt (IP gesperrt)? Aus dem Heimnetz wird nie gesperrt; sonst Container neu starten hebt Fehlversuch-Sperren auf,
  IP-Sperren unter Verwaltung → Angriffsschutz → Entsperren.
