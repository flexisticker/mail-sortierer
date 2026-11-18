# Postwart von außen erreichbar machen (Nginx Proxy Manager)

Ab Version 2.0 darf Postwart über das Internet erreichbar sein: Anmeldung mit Passwort **und** Code aus der
Authenticator-App (Pflicht für alle), Angriffsschutz mit Fallen und IP-Sperren, Verwaltung von außen nur nach erneuter Code-Eingabe.

## 1. DNS
Beim Anbieter der Domain einen A-Eintrag anlegen: `postwart.zatti.info` → deine feste IP (dieselbe wie bei `freigabe.flexisticker.de`).
Im Heimnetz (UniFi → Einstellungen → Routing/DNS → lokale DNS-Einträge) zusätzlich `postwart.zatti.info` → `192.168.1.111` (Nginx Proxy Manager).
Ohne diesen Eintrag landen Aufrufe von zu Hause über die öffentliche IP – Postwart hält dich dann für „unterwegs“ (Verwaltung nur mit Code, KI-Einstellungen gesperrt).
Zertifikatswarnung `*.alfahosting-server.de` o. Ä. = alter DNS-Zwischenspeicher → `ipconfig /flushdns` bzw. etwas warten.

## 2. Nginx Proxy Manager → Proxy Hosts → Add Proxy Host
- **Domain Names:** `postwart.zatti.info`
- **Scheme:** `http`, **Forward Hostname/IP:** `192.168.1.10`, **Forward Port:** `8110`
- **Block Common Exploits:** an · **Websockets Support:** egal
- **SSL:** „Request a new SSL Certificate“, **Force SSL** an, **HTTP/2** an, **HSTS** an
- **Keine** Access-List „Nur Heimnetz“ (sonst kommt man von außen nicht hin)
- Let's Encrypt prüft über Port 80 – der läuft bei dir schon über die UDM zum NPM (wie bei `freigabe.`).
- Anhänge bis 25 MB: NPM lässt standardmäßig große Uploads zu, nichts weiter einstellen.

Der Proxy reicht die echte Besucher-IP (`X-Forwarded-For`) und `https` (`X-Forwarded-Proto`) weiter – das ist bei NPM Standard.
Postwart übernimmt diese Angaben nur von Proxys aus dem eigenen Netz.

## 3. Vorher in Postwart
- Alle Nutzer haben die Zwei-Faktor-Anmeldung eingerichtet (Verwaltung → System → Nutzer).
- Verwaltung → System → Angriffsschutz: eingeschaltet.
- Schlüssel für die Passwörter als Unraid-Variable `POSTWART_SCHLUESSEL` (Verwaltung → System → Sicherheits-Check).

## 4. Prüfen
- Mit dem Handy über Mobilfunk `https://postwart.zatti.info` öffnen → Anmeldeseite.
- Verwaltung → **Sicherheits-Check**: „Zugriff von außen über HTTPS“ und „Echte Besucher-Adressen kommen an“ müssen grün sein.
- Verwaltung → **Angriffsschutz**: Nach einigen Stunden tauchen dort die ersten Bots auf – das ist normal.

## Was nur im Heimnetz geht
Gemeinsame KI (Ollama) und Einstellungen des Angriffsschutzes ändern. Nutzer verwalten (Passwort/2FA zurücksetzen, sperren …) geht
auch von unterwegs, aber nur nach erneuter Code-Eingabe (gilt 10 Minuten).

## Notfall
- Nutzer hat Passwort oder Handy verloren → Verwaltung → Nutzer → „Passwort zurücksetzen“ bzw. „2FA zurücksetzen“.
- Du selbst kommst nicht mehr rein → Unraid: Docker → Postwart → Console:
  `node src/reset-admin.js` (zeigt Konten) und `node src/reset-admin.js <name>` (Einmal-Passwort, 2FA wird neu eingerichtet).
- Selbst ausgesperrt (IP gesperrt)? Aus dem Heimnetz wird nie gesperrt; sonst Container neu starten hebt Fehlversuch-Sperren auf,
  IP-Sperren unter Verwaltung → Angriffsschutz → Entsperren.
