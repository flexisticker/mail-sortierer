// Angriffsschutz für den Mail-Sortierer (von außen erreichbar über Nginx Proxy Manager): Speicher, Einstellungen, Sicherheits-Check.
// Logik in shield-core.js (gleiche Datei wie in Vedly).
import crypto from 'node:crypto'
import { sysGet, sysSet, sysdb } from './db.js'
import { createShield, DEFAULT_SHIELD, KINDS, parseAllow, normIp, formFields as coreFields, checkForm as coreCheck } from './shield-core.js'
import { updateState } from './updates.js'
import { VERSION } from './html.js'
import { licenseState } from './license.js'
import { keySource, KEY_ENV } from './secrets.js'

export { KINDS }
export const shield = createShield({
  store: { load: () => sysGet('shield', null), save: (s) => sysSet('shield', s) },
  config: () => ({ ...DEFAULT_SHIELD, mail: 'off', ...(sysGet('shieldConfig', {}) || {}) })
})
process.on('exit', () => shield.flush())

// Woher kommen die Anfragen? (Prüft, ob der Proxy die echte Besucher-IP weiterreicht, und ob HTTPS ankommt.)
const seen = { public: 0, private: 0, lastPublic: '', https: 0, http: 0, since: new Date().toISOString() }
export function noteVisitor (req) {
  const why = shield.allowedWhy(req.ip)
  if (why === 'localhost' || why === 'Heimnetz') seen.private++
  else { seen.public++; seen.lastPublic = new Date().toISOString() }
  if (req.secure) seen.https++; else seen.http++
}

// Heimnetz = direkter Zugriff im eigenen Netz (oder über den Proxy aus dem eigenen Netz)
export function isHome (req) {
  const why = shield.allowedWhy(req.ip)
  return why === 'localhost' || why === 'Heimnetz'
}

// ------------------------------------------------------------ Formular-Fallen (Anmeldung)
function formSecret () {
  let s = sysGet('shieldFormSecret')
  if (!s) { s = crypto.randomBytes(32).toString('hex'); sysSet('shieldFormSecret', s) }
  return s
}
export const loginTrap = () => shield.config().enabled === false ? '' : coreFields(formSecret())
/** null = in Ordnung, sonst Meldung */
export function checkLoginForm (req) {
  if (shield.config().enabled === false) return null
  const r = coreCheck(req.body, formSecret(), { minMs: 1200 })
  if (r.kind) { shield.strike(req.ip, r.kind, { where: 'app', path: req.originalUrl, ua: req.get('user-agent') || '' }); return 'Die Anmeldung konnte nicht verarbeitet werden. Bitte die Seite neu laden.' }
  if (r.stale) return 'Die Anmeldeseite war veraltet – bitte noch einmal versuchen.'
  return null
}

// ------------------------------------------------------------ Einstellungen
export function saveShieldConfig (b = {}) {
  const cur = shield.config()
  const allow = String(b.allow || '').split(/[\s,;]+/).map(x => x.trim()).filter(Boolean)
  const bad = allow.filter(s => !parseAllow(s))
  if (bad.length) throw new Error(`Ungültige Ausnahme: ${bad.slice(0, 3).join(', ')} (erlaubt: 1.2.3.4, 1.2.3.0/24, 2a01:db8::/48)`)
  const next = {
    enabled: b.enabled === '1',
    ban: b.ban === '1',
    allowLan: b.allowLan === '1',
    tarpit: b.tarpit === '1',
    mail: 'off',
    allow: [...new Set(allow.map(s => parseAllow(s).text))].slice(0, 100)
  }
  sysSet('shieldConfig', next)
  return { ...cur, ...next }
}
export function manualBan (ip, user, hours) {
  const a = normIp(ip)
  if (!parseAllow(a) || a.includes('/')) throw new Error('Bitte eine einzelne IP-Adresse angeben.')
  const why = shield.allowedWhy(a)
  if (why) throw new Error(`Diese Adresse wird nie gesperrt (${why}).`)
  const h = Math.min(24 * 365, Math.max(1, Number(hours) || 24))
  return shield.ban(a, { reason: 'manual', detail: `von ${user}`, ms: h * 3600000, by: user, where: 'hand' })
}

// ------------------------------------------------------------ Sicherheits-Check (Ampel)
const fmt = (v) => new Date(v).toLocaleString('de-DE', { timeZone: 'Europe/Berlin', dateStyle: 'medium', timeStyle: 'short' })
export function selfCheck () {
  const out = []
  const add = (state, title, text) => out.push({ state, title, text })
  const cfg = shield.config()
  if (cfg.enabled === false) add('bad', 'Angriffsschutz ist ausgeschaltet', 'Fallen und Sperren wirken nicht. Unter „Angriffsschutz“ wieder einschalten.')
  else if (cfg.ban === false) add('warn', 'Nur protokollieren', 'Angriffe werden erkannt, aber niemand wird gesperrt.')
  else add('ok', 'Angriffsschutz aktiv', 'Fallen, Angriffsmuster und IP-Sperren sind eingeschaltet.')
  if (cfg.allowLan === false) add('warn', 'Heimnetz wird nicht ausgenommen', 'Auch Geräte im eigenen Netz können gesperrt werden – Vorsicht, du könntest dich selbst aussperren.')
  // Zwei-Faktor
  const users = sysdb.prepare('SELECT name, totp_on, disabled FROM users').all().filter(u => !u.disabled)
  const missing = users.filter(u => !u.totp_on).map(u => u.name)
  if (missing.length) add('warn', 'Zwei-Faktor noch nicht eingerichtet', `Diese Nutzer haben die Authenticator-App noch nicht eingerichtet (passiert bei der nächsten Anmeldung): ${missing.join(', ')}.`)
  else add('ok', 'Zwei-Faktor für alle aktiv', `${users.length} Nutzer, alle mit Authenticator-App.`)
  // Von außen: HTTPS + echte IP
  if (seen.public) {
    add(seen.http && !seen.https ? 'bad' : 'ok', seen.https ? 'Zugriff von außen über HTTPS' : 'Zugriff von außen ohne HTTPS', seen.https ? 'Der Proxy meldet HTTPS – Anmeldedaten und Mails gehen verschlüsselt über das Internet.' : 'Anfragen kommen unverschlüsselt an. Im Nginx Proxy Manager „Force SSL“ einschalten.')
    add('ok', 'Echte Besucher-Adressen kommen an', `Der Proxy reicht die IP der Besucher weiter – Sperren treffen den Richtigen. Zuletzt von außen: ${fmt(seen.lastPublic)}.`)
  } else if (seen.private > 30) add('info', 'Bisher nur Zugriffe aus dem Heimnetz', `Seit ${fmt(seen.since)} kamen alle ${seen.private} Anfragen aus dem Heimnetz. Ist Postwart schon über den Proxy freigegeben, kommt die echte IP nicht an (X-Forwarded-For fehlt) – dann wirken Sperren nicht.`)
  else add('info', 'Zugriff von außen noch nicht geprüft', 'Seit dem letzten Neustart kamen noch keine Anfragen von außen.')
  // Schlüssel der gespeicherten Passwörter
  const ks = keySource()
  if (ks === 'env') add('ok', 'Passwort-Schlüssel getrennt abgelegt', `Der Schlüssel kommt aus der Variable ${KEY_ENV} – eine Kopie des Datenordners allein reicht nicht, um die Postfach-Passwörter zu lesen.`)
  else if (ks === 'dpapi') add('ok', 'Passwort-Schlüssel mit Windows-Datenschutz geschützt', 'Der Schlüssel ist an diesen Rechner gebunden – auf einem anderen Rechner ist eine Kopie des Datenordners unlesbar.')
  else add('warn', 'Passwort-Schlüssel liegt im Datenordner', `Wer den ganzen Datenordner (z. B. eine Sicherung) bekommt, kann die Postfach-Passwörter entschlüsseln. Besser: Schlüssel als Variable ${KEY_ENV} im Container eintragen (unten „Schlüssel anzeigen“).`)
  // Updates
  const up = updateState()
  if (up && up.update) add('warn', 'Update verfügbar', `Installiert ${VERSION}, verfügbar ${up.latest}. Sicherheitskorrekturen kommen mit den Updates (Unraid: „Check for Updates“ → „apply update“).`)
  else if (up && up.latest) add('ok', 'Software aktuell', `Version ${VERSION} (geprüft ${fmt(up.at)}).`)
  else add('info', 'Update-Prüfung noch nicht gelaufen', up && up.error ? `Fehler: ${up.error}` : 'Wird kurz nach dem Start einmal am Tag geprüft.')
  // Lizenz
  const L = licenseState()
  if (!L.exempt && !L.full) add('warn', 'Lizenz', L.message)
  return out
}
