# Postwart: Zwei-Faktor-Anmeldung einrichten (Anleitung für Nutzer)

Bei Postwart meldest du dich mit **Passwort und einem 6-stelligen Code** an. Den Code erzeugt eine Authenticator-App auf deinem Handy,
er ändert sich alle 30 Sekunden. Die Einrichtung macht man **einmal** bei der ersten Anmeldung.

## Vorher: App installieren
Eine dieser kostenlosen Apps aus dem Play Store (Android) bzw. App Store (iPhone):
- **Authy** (Twilio) – fragt beim ersten Start nach Handynummer und E-Mail (für Authy selbst), kann die Codes verschlüsselt sichern
- Google Authenticator, Microsoft Authenticator, 2FAS – gehen genauso

## A) Du richtest am Handy ein (Postwart ist auf dem Handy offen)
Den QR-Code kann das Handy nicht scannen, weil er auf demselben Bildschirm steht – du kopierst stattdessen den Schlüssel.
1. In Postwart bei „Ich richte am Handy ein“ auf **Kopieren** tippen (klappt das nicht: lange auf das Feld drücken → Alles auswählen → Kopieren).
2. **Authy öffnen** → **+** („Konto hinzufügen“).
3. **„Enter key manually“ / „Code manuell eingeben“** wählen – nicht „QR-Code scannen“.
4. Ins Schlüsselfeld **lange drücken → Einfügen**. Name z. B. „Postwart“. Falls gefragt: zeitbasiert, **6 Ziffern**, 30 Sekunden. Speichern.
5. Authy zeigt einen **6-stelligen Code**: auf den Eintrag tippen und **Kopieren** (Google Authenticator: lange auf den Code drücken).
6. **Zurück in den Browser**, den Code bei „Code aus der App“ einfügen (oder abtippen) → **Bestätigen**.

Google Authenticator und 2FAS können den Eintrag auch direkt übernehmen: Knopf „In Authenticator-App öffnen“.

## B) Du richtest am PC ein (Handy liegt daneben)
1. Authy öffnen → **+** → **„QR-Code scannen“**.
2. Den QR-Code auf dem PC-Bildschirm scannen.
3. Den 6-stelligen Code aus der App in Postwart eingeben → **Bestätigen**.

## Danach: Notfallcodes aufbewahren
Postwart zeigt **10 Notfallcodes** – nur ein einziges Mal. Ausdrucken oder abschreiben und sicher aufbewahren.
Damit kommst du herein, wenn das Handy weg ist (jeder Code gilt einmal).

## Bei jeder Anmeldung
Passwort eingeben → Authy öffnen → Code bei „Postwart“ abtippen oder kopieren und einfügen.
Mit „Angemeldet bleiben“ fragt Postwart auf diesem Gerät 30 Tage nicht erneut.

## Probleme
- **Code wird nicht angenommen:** Uhrzeit am Handy auf „automatisch“ stellen; immer den aktuellen Code nehmen.
- **7 oder 8 Ziffern in der App:** Eintrag löschen und mit 6 Ziffern neu anlegen.
- **Neues Handy / App gelöscht:** mit einem Notfallcode anmelden, oder den Verwalter bitten, die Zwei-Faktor-Anmeldung zurückzusetzen –
  dann richtest du sie bei der nächsten Anmeldung neu ein. (Mit eingeschalteter Authy-Sicherung sind die Codes auf dem neuen Handy schon da.)
