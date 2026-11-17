// Anmeldung: ein Konto (Admin), scrypt 2^16 mit Salt, Sitzungen nur als SHA-256 gespeichert.
import crypto from 'node:crypto'
import { promisify } from 'node:util'
import { db, now } from './db.js'

const scrypt = promisify(crypto.scrypt)
const N = 2 ** 16
const SESSION_DAYS = 30          // „Angemeldet bleiben“
const SHORT_MS = 12 * 3600 * 1000 // ohne Haken: 12 Stunden ohne Nutzung, Cookie endet mit dem Browser
// Spalte für „Angemeldet bleiben“ (ältere Datenbanken)
if (!db.prepare('PRAGMA table_info(sessions)').all().some(c => c.name === 'remember')) db.exec('ALTER TABLE sessions ADD COLUMN remember INTEGER NOT NULL DEFAULT 1')

export async function hashPassword (pw) {
  const salt = crypto.randomBytes(16)
  const h = await scrypt(String(pw).normalize('NFKC'), salt, 64, { N, r: 8, p: 1, maxmem: 2 ** 27 })
  return `scrypt$16$${salt.toString('base64')}$${h.toString('base64')}`
}

export async function verifyPassword (pw, stored) {
  const [alg, logN, salt, hash] = String(stored || '').split('$')
  if (alg !== 'scrypt' || !salt || !hash) return false
  const n = 2 ** Number(logN)
  const want = Buffer.from(hash, 'base64')
  const got = await scrypt(String(pw).normalize('NFKC'), Buffer.from(salt, 'base64'), want.length, { N: n, r: 8, p: 1, maxmem: n * 2048 })
  return crypto.timingSafeEqual(want, got)
}

export const hasUsers = () => !!db.prepare('SELECT 1 FROM users LIMIT 1').get()

export async function createUser (name, pw) {
  db.prepare('INSERT INTO users (name, hash, created_at) VALUES (?, ?, ?)').run(name, await hashPassword(pw), now())
}

export async function changePassword (userId, pw) {
  db.prepare('UPDATE users SET hash = ? WHERE id = ?').run(await hashPassword(pw), userId)
  db.prepare('DELETE FROM sessions WHERE user_id = ?').run(userId)
}

const sha = (s) => crypto.createHash('sha256').update(s).digest('hex')

// Fehlversuche je IP und je Benutzername (nur im Speicher; Neustart hebt die Sperre auf)
const fails = new Map()
function tooMany (key) {
  const f = fails.get(key)
  return f && f.count >= 5 && Date.now() - f.at < 15 * 60 * 1000
}
function fail (key) {
  const f = fails.get(key)
  if (!f || Date.now() - f.at > 15 * 60 * 1000) fails.set(key, { count: 1, at: Date.now() })
  else { f.count++; f.at = Date.now() }
}

const DUMMY = 'scrypt$16$AAAAAAAAAAAAAAAAAAAAAA==$' + Buffer.alloc(64).toString('base64')

export async function login (name, pw, ip, remember = true) {
  if (tooMany('ip:' + ip) || tooMany('name:' + name)) return { error: 'Zu viele Fehlversuche – bitte 15 Minuten warten.' }
  const u = db.prepare('SELECT * FROM users WHERE name = ?').get(String(name || ''))
  const ok = await verifyPassword(pw, u ? u.hash : DUMMY)
  if (!u || !ok) {
    fail('ip:' + ip); fail('name:' + name)
    return { error: 'Benutzername oder Passwort falsch.' }
  }
  fails.delete('ip:' + ip); fails.delete('name:' + name)
  const token = crypto.randomBytes(32).toString('base64url')
  const csrf = crypto.randomBytes(24).toString('base64url')
  db.prepare('INSERT INTO sessions (token_hash, user_id, csrf, expires_at, remember) VALUES (?, ?, ?, ?, ?)')
    .run(sha(token), u.id, csrf, Date.now() + (remember ? SESSION_DAYS * 864e5 : SHORT_MS), remember ? 1 : 0)
  return { token, remember }
}

export function sessionFor (token) {
  if (!token) return null
  const s = db.prepare('SELECT s.*, u.name FROM sessions s JOIN users u ON u.id = s.user_id WHERE token_hash = ?').get(sha(token))
  if (!s || s.expires_at < Date.now()) return null
  // gleitend verlängern (bei „Angemeldet bleiben“ höchstens einmal am Tag, dann wird auch das Cookie erneuert)
  let renewed = false
  if (s.remember && s.expires_at - Date.now() < (SESSION_DAYS - 1) * 864e5) {
    db.prepare('UPDATE sessions SET expires_at = ? WHERE token_hash = ?').run(Date.now() + SESSION_DAYS * 864e5, s.token_hash)
    renewed = true
  } else if (!s.remember && s.expires_at - Date.now() < SHORT_MS - 5 * 60000) {
    db.prepare('UPDATE sessions SET expires_at = ? WHERE token_hash = ?').run(Date.now() + SHORT_MS, s.token_hash)
  }
  return { userId: s.user_id, name: s.name, csrf: s.csrf, tokenHash: s.token_hash, remember: !!s.remember, renewed }
}

export function logout (token) {
  if (token) db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(sha(token))
}
