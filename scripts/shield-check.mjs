// Prüft den Angriffsschutz (src/shield-core.js): keine Fehlalarme bei Adressen des Mail-Sortierers und normalen Browsern, Fallen greifen.
// Läuft in der Action (Job „secrets“) und lokal: node scripts/shield-check.mjs
import { inspect, checkForm, formFields, parseAllow } from '../src/shield-core.js'

let bad = 0
const fail = (m) => { bad++; console.error('FEHLER:', m) }

// Adressen des Mail-Sortierers – dürfen nie als Angriff gelten (neue Seiten hier ergänzen!)
const OK_PATHS = ['/', '/anmelden', '/anmelden/code', '/anmelden/passwort', '/anmelden/einrichten-2fa', '/einrichten', '/abmelden', '/health', '/robots.txt',
  '/app.css', '/app.js', '/editor.js', '/icon.svg', '/icon.png', '/mails', '/mails/12/korrektur', '/rechnungen', '/rechnungen/5/datei', '/gelernt', '/protokoll',
  '/einstellungen', '/einstellungen/sicherheit', '/verwaltung', '/verwaltung/ki', '/verwaltung/schutz', '/verwaltung/check', '/verwaltung/nutzer/3',
  '/post', '/post/1', '/uebersicht', '/post/1/lesen', '/post/1/inhalt', '/post/1/anhang', '/post/1/aktion', '/post/neu', '/post/senden', '/signaturen', '/.well-known/acme-challenge/abc']
for (const p of OK_PATHS) { const r = inspect({ path: p, url: p }); if (r) fail(`Fehlalarm bei ${p}: ${r.kind}`) }
const OK_QUERIES = ['/post/1?ordner=INBOX&seite=2&q=M%C3%BCller%20%26%20S%C3%B6hne', '/post/1?ordner=INBOX&uid=4711&bilder=1', '/post/1/lesen?ordner=Sortiert.Rechnungen&uid=4711', '/mails?q=Rechnung%20Oktober&status=moved',
  '/rechnungen?jahr=2026&monat=11', '/post/1/anhang?ordner=INBOX&uid=5&teil=2', '/post/neu?postfach=1&antwort=5&ordner=INBOX&art=alle']
for (const u of OK_QUERIES) { const r = inspect({ path: u.split('?')[0], url: u }); if (r) fail(`Fehlalarm bei ${u}: ${r.kind}`) }

const OK_UA = ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0',
  'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1',
  'Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0', 'Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Mobile Safari/537.36',
  'curl/8.5.0', 'node']
for (const ua of OK_UA) { const r = inspect({ path: '/', url: '/', ua }); if (r) fail(`Fehlalarm bei Browser ${ua}: ${r.kind}`) }

const TRAPS = ['/wp-admin/', '/wp-login.php', '/xmlrpc.php', '/.env', '/.git/config', '/phpmyadmin/', '/backup.sql', '/cgi-bin/luci', '/vendor/phpunit/x', '/index.php', '/owa/auth/logon.aspx']
for (const p of TRAPS) if (inspect({ path: p, url: p })?.kind !== 'trap') fail(`Falle greift nicht: ${p}`)
const ATTACKS = ['/post/1?ordner=../../etc/passwd', '/?q=1%27%20UNION%20SELECT%20password%20FROM%20users', '/?x=%24%7Bjndi:ldap://x/a%7D', '/?s=<script>alert(1)</script>']
for (const u of ATTACKS) if (inspect({ path: '/', url: u })?.kind !== 'attack') fail(`Angriffsmuster nicht erkannt: ${u}`)
for (const ua of ['sqlmap/1.7.2#stable', 'Mozilla/5.00 (Nikto/2.5.0)', 'WPScan v3.8']) if (inspect({ path: '/', url: '/', ua })?.kind !== 'scanner') fail(`Scanner nicht erkannt: ${ua}`)

const sec = 'test'
const ft = (at) => formFields(sec, at).match(/name="ft" value="([^"]+)"/)[1]
if (!checkForm({ ft: ft(Date.now() - 5000) }, sec).ok) fail('Formular normal abgelehnt')
if (checkForm({ ft: ft(Date.now()) }, sec).kind !== 'fast') fail('zu schnelles Formular nicht erkannt')
if (checkForm({ ft: ft(Date.now() - 5000), website: 'http://spam' }, sec).kind !== 'honeypot') fail('unsichtbares Feld nicht erkannt')
if (parseAllow('0.0.0.0/0') || !parseAllow('192.168.1.0/24')) fail('Ausnahmeliste prüft falsch')

if (bad) { console.error(`${bad} Fehler im Angriffsschutz`); process.exit(1) }
console.log('Angriffsschutz: alle Prüfungen bestanden')
