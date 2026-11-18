// Geheimnisse (IMAP-Passwort) verschlüsselt speichern: AES-256-GCM, Schlüssel in DATA_DIR/.schluessel (nur für den Container lesbar).
// Schützt davor, dass das Passwort im Klartext in der Datenbank oder in einer Datenbank-Kopie steht.
import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { DATA_DIR, kvGet, kvSet } from './db.js'

const KEY_FILE = path.join(DATA_DIR, '.schluessel')

function key () {
  if (!fs.existsSync(KEY_FILE)) {
    fs.writeFileSync(KEY_FILE, crypto.randomBytes(32).toString('base64'), { mode: 0o600 })
  }
  const k = Buffer.from(fs.readFileSync(KEY_FILE, 'utf8').trim(), 'base64')
  if (k.length !== 32) throw new Error('Schlüsseldatei .schluessel ist beschädigt')
  return k
}

/** Einzelnen Wert verschlüsseln/entschlüsseln (z. B. 2FA-Geheimnis in der Benutzertabelle) */
export function encrypt (value) {
  const iv = crypto.randomBytes(12)
  const c = crypto.createCipheriv('aes-256-gcm', key(), iv)
  const enc = Buffer.concat([c.update(String(value), 'utf8'), c.final()])
  return [iv, c.getAuthTag(), enc].map(b => b.toString('base64')).join('.')
}
export function decrypt (v) {
  if (!v) return ''
  try {
    const [iv, tag, enc] = String(v).split('.').map(s => Buffer.from(s, 'base64'))
    const d = crypto.createDecipheriv('aes-256-gcm', key(), iv)
    d.setAuthTag(tag)
    return Buffer.concat([d.update(enc), d.final()]).toString('utf8')
  } catch { return '' }
}

export function setSecret (name, value) {
  const all = kvGet('secrets', {})
  if (!value) { delete all[name]; kvSet('secrets', all); return }
  const iv = crypto.randomBytes(12)
  const c = crypto.createCipheriv('aes-256-gcm', key(), iv)
  const enc = Buffer.concat([c.update(String(value), 'utf8'), c.final()])
  all[name] = [iv, c.getAuthTag(), enc].map(b => b.toString('base64')).join('.')
  kvSet('secrets', all)
}

export function getSecret (name) {
  const v = kvGet('secrets', {})[name]
  if (!v) return ''
  try {
    const [iv, tag, enc] = v.split('.').map(s => Buffer.from(s, 'base64'))
    const d = crypto.createDecipheriv('aes-256-gcm', key(), iv)
    d.setAuthTag(tag)
    return Buffer.concat([d.update(enc), d.final()]).toString('utf8')
  } catch {
    return ''
  }
}

export const hasSecret = (name) => !!kvGet('secrets', {})[name]
