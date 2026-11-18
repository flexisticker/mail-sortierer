// Geheimnisse (Postfach-/SMTP-Passwörter, Lexware-Schlüssel, 2FA-Geheimnisse) verschlüsselt speichern: AES-256-GCM.
// Woher kommt der Schlüssel? (in dieser Reihenfolge)
//   1. Umgebungsvariable POSTWART_SCHLUESSEL (Unraid: Variable im Container) – liegt dann NICHT im Datenordner:
//      eine gestohlene Sicherung des Datenordners enthält zwar die verschlüsselten Passwörter, aber nicht den Schlüssel.
//   2. Windows: Datei .schluessel.dpapi – mit dem Windows-Datenschutz (DPAPI, Rechner-Schlüssel) geschützt, auf einem anderen Rechner unlesbar.
//   3. Datei DATA_DIR/.schluessel (nur für den Container lesbar) – Rückfall.
// Beim Umstieg (Variable neu gesetzt, Datei vorhanden) wird alles einmal mit dem neuen Schlüssel neu verschlüsselt und die Datei entfernt.
import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { execFileSync } from 'node:child_process'
import { DATA_DIR, kvGet, kvSet, sysdb, sysGet, sysSet } from './db.js'

const KEY_FILE = path.join(DATA_DIR, '.schluessel')
const DPAPI_FILE = path.join(DATA_DIR, '.schluessel.dpapi')
export const KEY_ENV = 'POSTWART_SCHLUESSEL'
const isWin = process.platform === 'win32'
let cached = null
let source = ''

const parseKey = (s, what) => {
  const k = Buffer.from(String(s || '').trim(), 'base64')
  if (k.length !== 32) throw new Error(`${what} ist kein gültiger Schlüssel (erwartet: 32 Byte als Base64, 44 Zeichen).`)
  return k
}
const readFileKey = () => fs.existsSync(KEY_FILE) ? parseKey(fs.readFileSync(KEY_FILE, 'utf8'), 'Die Datei .schluessel') : null

// --- Windows-Datenschutz (DPAPI, Rechner-Bereich) über die eingebaute Windows PowerShell ---
function ps (script, value) {
  return execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command',
    'Add-Type -AssemblyName System.Security; ' + script], { env: { ...process.env, PW_K: value }, encoding: 'utf8', windowsHide: true, timeout: 30000 }).trim()
}
const dpapiProtect = (key) => ps("[Convert]::ToBase64String([Security.Cryptography.ProtectedData]::Protect([Convert]::FromBase64String($env:PW_K), $null, 'LocalMachine'))", key.toString('base64'))
const dpapiUnprotect = (blob) => parseKey(ps("[Convert]::ToBase64String([Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String($env:PW_K), $null, 'LocalMachine'))", blob), 'Der geschützte Schlüssel')

function writeDpapi (key) {
  const blob = dpapiProtect(key)
  if (!dpapiUnprotect(blob).equals(key)) throw new Error('DPAPI-Prüfung fehlgeschlagen')
  fs.writeFileSync(DPAPI_FILE, blob)
}

/** Schlüssel bestimmen (einmal beim Start, auch für Konsolen-Skripte) */
function key () {
  if (cached) return cached
  const envVal = process.env[KEY_ENV]
  if (envVal) { cached = parseKey(envVal, `Die Variable ${KEY_ENV}`); source = 'env'; return cached }
  if (isWin) {
    // vorhandene geschützte Datei nie umgehen: lieber Start abbrechen als einen zweiten Schlüssel anlegen
    if (fs.existsSync(DPAPI_FILE)) { cached = dpapiUnprotect(fs.readFileSync(DPAPI_FILE, 'utf8')); source = 'dpapi'; return cached }
    try {
      const k = readFileKey() || crypto.randomBytes(32)
      writeDpapi(k)
      if (fs.existsSync(KEY_FILE)) fs.rmSync(KEY_FILE)
      cached = k; source = 'dpapi'; return cached
    } catch (e) {
      console.error('[postwart] Windows-Datenschutz nicht verfügbar, Schlüssel bleibt als Datei:', e.message)
    }
  }
  if (!fs.existsSync(KEY_FILE)) {
    if (sysGet('keyCheck', null)) throw new Error(`Der Schlüssel für die gespeicherten Passwörter fehlt (Variable ${KEY_ENV} oder Datei .schluessel).`)
    fs.writeFileSync(KEY_FILE, crypto.randomBytes(32).toString('base64'), { mode: 0o600 })
  }
  cached = readFileKey(); source = 'file'
  return cached
}
export const keySource = () => { key(); return source }

function enc (value, k) {
  const iv = crypto.randomBytes(12)
  const c = crypto.createCipheriv('aes-256-gcm', k, iv)
  const e = Buffer.concat([c.update(String(value), 'utf8'), c.final()])
  return [iv, c.getAuthTag(), e].map(b => b.toString('base64')).join('.')
}
function dec (v, k) {
  const [iv, tag, e] = String(v).split('.').map(s => Buffer.from(s, 'base64'))
  const d = crypto.createDecipheriv('aes-256-gcm', k, iv)
  d.setAuthTag(tag)
  return Buffer.concat([d.update(e), d.final()]).toString('utf8')
}

/** Einzelnen Wert verschlüsseln/entschlüsseln (z. B. 2FA-Geheimnis in der Benutzertabelle) */
export const encrypt = (value) => enc(value, key())
export function decrypt (v) { if (!v) return ''; try { return dec(v, key()) } catch { return '' } }

export function setSecret (name, value) {
  const all = kvGet('secrets', {})
  if (!value) { delete all[name]; kvSet('secrets', all); return }
  all[name] = enc(value, key())
  kvSet('secrets', all)
}
export function getSecret (name) {
  const v = kvGet('secrets', {})[name]
  if (!v) return ''
  try { return dec(v, key()) } catch { return '' }
}
export const hasSecret = (name) => !!kvGet('secrets', {})[name]

/**
 * Beim Start: Schlüssel prüfen und ggf. umziehen. eachUserDb(fn) ruft fn(db) für jede Nutzer-Datenbank (außer der Haupt-Datenbank) auf.
 * - Variable gesetzt, alte Datei vorhanden → alles neu verschlüsseln, Datei löschen.
 * - Prüfwert (sys-kv keyCheck) lässt sich nicht entschlüsseln → falscher Schlüssel: Start abbrechen, damit nichts überschrieben wird.
 */
export function prepareKey (eachUserDb) {
  const check = sysGet('keyCheck', null)
  const fits = (k) => { if (!check) return true; try { return dec(check, k) === 'postwart' } catch { return false } }
  const readOld = () => {
    const list = []
    try { const f = readFileKey(); if (f) list.push(f) } catch { /* kaputt */ }
    if (isWin && fs.existsSync(DPAPI_FILE)) { try { list.push(dpapiUnprotect(fs.readFileSync(DPAPI_FILE, 'utf8'))) } catch { /* nicht lesbar */ } }
    return list.find(fits) || list[0] || null
  }
  const envVal = process.env[KEY_ENV]
  if (envVal) {
    const newKey = parseKey(envVal, `Die Variable ${KEY_ENV}`)
    const oldKey = readOld()
    if (check) {
      if (!fits(newKey)) {
        if (oldKey && fits(oldKey)) console.log(`[postwart] Schlüssel aus ${KEY_ENV} übernommen, ${reencrypt(oldKey, newKey, eachUserDb)} Geheimnisse neu verschlüsselt`)
        else throw new Error(`Die Variable ${KEY_ENV} passt nicht zu den gespeicherten Passwörtern. Start abgebrochen, damit nichts verloren geht – bitte den richtigen Schlüssel eintragen.`)
      }
    } else if (oldKey && !oldKey.equals(newKey)) {
      console.log(`[postwart] Schlüssel aus ${KEY_ENV} übernommen, ${reencrypt(oldKey, newKey, eachUserDb)} Geheimnisse neu verschlüsselt`)
    }
    for (const f of [KEY_FILE, DPAPI_FILE]) if (fs.existsSync(f)) fs.rmSync(f)
    cached = newKey; source = 'env'
    sysSet('keyCheck', enc('postwart', newKey))
    return source
  }
  // ohne Variable: gibt es schon Passwörter, darf nie still ein neuer Schlüssel entstehen
  if (check && !fs.existsSync(KEY_FILE) && !(isWin && fs.existsSync(DPAPI_FILE))) {
    throw new Error(`Der Schlüssel für die gespeicherten Passwörter fehlt (Variable ${KEY_ENV} oder Datei .schluessel). Start abgebrochen, damit nichts verloren geht.`)
  }
  const k = key()
  if (!fits(k)) throw new Error('Der Schlüssel passt nicht zu den gespeicherten Passwörtern. Start abgebrochen, damit nichts verloren geht.')
  if (!check) sysSet('keyCheck', enc('postwart', k))
  return source
}

function reencrypt (oldKey, newKey, eachUserDb) {
  let n = 0
  const fix = (db) => {
    const row = db.prepare("SELECT v FROM kv WHERE k = 'secrets'").get()
    if (!row) return
    const all = JSON.parse(row.v || '{}')
    for (const [name, v] of Object.entries(all)) { try { all[name] = enc(dec(v, oldKey), newKey); n++ } catch { /* unlesbar – bleibt */ } }
    db.prepare("UPDATE kv SET v = ? WHERE k = 'secrets'").run(JSON.stringify(all))
  }
  fix(sysdb)
  eachUserDb(fix)
  for (const u of sysdb.prepare('SELECT id, totp_secret FROM users WHERE totp_secret IS NOT NULL').all()) {
    try { sysdb.prepare('UPDATE users SET totp_secret = ? WHERE id = ?').run(enc(dec(u.totp_secret, oldKey), newKey), u.id); n++ } catch { /* unlesbar */ }
  }
  return n
}

/** Aktuellen Schlüssel anzeigen (nur Verwalter im Heimnetz) – zum Eintragen als Variable */
export const currentKeyBase64 = () => key().toString('base64')
