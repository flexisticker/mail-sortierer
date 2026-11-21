// Anmeldung (ab 2.0 mehrere Nutzer): scrypt 2^16 mit Salt, Sitzungen nur als SHA-256, Zwei-Faktor (TOTP) Pflicht für alle.
// Sitzungs-Stufen: pw (neues Passwort nötig) → enroll (2FA einrichten) bzw. mfa (Code eingeben) → full.
// Alles hier liegt in der Haupt-Datenbank (sysdb), nie in den Nutzer-Datenbanken.
import crypto from 'node:crypto'
import { promisify } from 'node:util'
import { sysdb as db, now, sysLog, dropUserData } from './db.js'
import { encrypt, decrypt } from './secrets.js'
import { newSecret, verifyTotp, newRecoveryCodes, useRecoveryCode, sha } from './totp.js'

const scrypt = promisify(crypto.scrypt)
const N = 2 ** 16
const SESSION_DAYS = 30          // „Angemeldet bleiben“
const SHORT_MS = 12 * 3600 * 1000 // ohne Haken: 12 Stunden ohne Nutzung, Cookie endet mit dem Browser
const STAGE_MS = 15 * 60 * 1000   // bis 2FA/Passwort erledigt sind
const STEPUP_MS = 10 * 60 * 1000  // Verwaltung von außen: Code gilt 10 Minuten

// Bestand vor 2.0: das älteste Konto ist Verwalter und nutzt die Haupt-Datenbank
;(function migrate () {
  if (!db.prepare("SELECT 1 FROM users WHERE role = 'admin'").get()) {
    const first = db.prepare('SELECT id FROM users ORDER BY id LIMIT 1').get()
    if (first) db.prepare("UPDATE users SET role = 'admin', data = '' WHERE id = ?").run(first.id)
  }
})()

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
export const getUser = (id) => db.prepare('SELECT * FROM users WHERE id = ?').get(Number(id))
export const listUsers = () => db.prepare('SELECT * FROM users ORDER BY id').all()
export const activeUsers = () => db.prepare('SELECT * FROM users WHERE disabled = 0 ORDER BY id').all()
export const validName = (n) => /^[A-Za-z0-9ÄÖÜäöüß._@-]{2,40}$/.test(String(n || ''))

// Bereiche, die der Verwalter je Nutzer an- und abschalten kann
export const FEATURES = {
  invoices: 'Rechnungen sammeln (Sammel-Postfach, Monatsordner)',
  lexware: 'Rechnungen an Lexware Office übertragen',
  scan: 'Scanner-Ordner abholen',
  cleanup: 'Spam und Verdacht aufräumen (löschen)',
  folders: 'Eigene Ordner anlegen und Ordner umbenennen',
  webmail: 'Mail-Programm (Mails lesen und schreiben)',
  manage: 'Sortierung sehen und prüfen (Übersicht, Sortierung, Gelernt, Protokoll)'
}
export const FULL_FEATURES = Object.fromEntries(Object.keys(FEATURES).map(k => [k, true]))
export const SIMPLE_FEATURES = { invoices: false, lexware: false, scan: false, cleanup: true, folders: true, webmail: true, manage: false }
export function featuresOf (u) {
  if (!u) return { ...FULL_FEATURES }
  if (!u.features) return u.role === 'admin' ? { ...FULL_FEATURES } : { ...SIMPLE_FEATURES }
  let f = {}
  try { f = JSON.parse(u.features) } catch { f = {} }
  return Object.fromEntries(Object.keys(FEATURES).map(k => [k, f[k] !== undefined ? !!f[k] : (u.role === 'admin' || SIMPLE_FEATURES[k])]))
}

/** Konto anlegen. Erstes Konto = Verwalter mit Haupt-Datenbank, weitere bekommen eine eigene Datenbank. */
export async function createUser (name, pw, { role = 'user', display = '', features = null, mustChange = false } = {}) {
  if (!validName(name)) throw new Error('Benutzername: 2–40 Zeichen, nur Buchstaben, Ziffern und . _ - @')
  if (db.prepare('SELECT 1 FROM users WHERE lower(name) = lower(?)').get(name)) throw new Error('Diesen Benutzernamen gibt es schon.')
  const first = !hasUsers()
  const r = db.prepare('INSERT INTO users (name, hash, created_at, role, display, data, features, must_change) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
    .run(name, await hashPassword(pw), now(), first ? 'admin' : (role === 'admin' ? 'admin' : 'user'), String(display || '').slice(0, 60), '',
      features ? JSON.stringify(features) : null, mustChange ? 1 : 0)
  const id = Number(r.lastInsertRowid)
  if (!first) db.prepare('UPDATE users SET data = ? WHERE id = ?').run(`nutzer/${id}`, id)
  return getUser(id)
}

export async function changePassword (userId, pw, keepTokenHash = null) {
  if (String(pw || '').length < 10) throw new Error('Passwort zu kurz (mind. 10 Zeichen).')
  db.prepare('UPDATE users SET hash = ?, must_change = 0 WHERE id = ?').run(await hashPassword(pw), userId)
  if (keepTokenHash) db.prepare('DELETE FROM sessions WHERE user_id = ? AND token_hash <> ?').run(userId, keepTokenHash)
  else db.prepare('DELETE FROM sessions WHERE user_id = ?').run(userId)
}

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
  if (fails.size > 10000) fails.clear()
}
// Zwei-Faktor: falsche Codes je Konto, dauerhaft in users (überlebt Neustart und neue Sitzungen).
// Kundenvorgabe 21.11.2026 (alle Projekte): höchstens 10 Fehlversuche, dann Sperre.
export const MFA_MAX = 10
const MFA_WINDOW = 24 * 3600 * 1000 // Fehlversuche zählen 24 Std. ab dem letzten
const MFA_LOCK = 24 * 3600 * 1000   // so lange ist die Anmeldung danach gesperrt
let onMfaLock = () => {}
/** Wird bei einer neuen 2FA-Sperre aufgerufen: fn(ip, user) – z. B. IP im Angriffsschutz sperren */
export const setMfaLockHook = (fn) => { onMfaLock = fn }
export const mfaLockedUntil = (u) => u && Number(u.mfa_locked_until) > Date.now() ? Number(u.mfa_locked_until) : 0
const untilText = (ms) => new Date(ms).toLocaleString('de-DE', { timeZone: process.env.TZ || 'Europe/Berlin', day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' })
export const mfaLockText = (ms) => `Zu viele falsche Zwei-Faktor-Codes – die Anmeldung ist bis ${untilText(ms)} Uhr gesperrt (auch mit Notfallcode). Der Verwalter kann die Sperre aufheben.`
/** Falscher Code: zählen, beim 10. sperren (Konto 24 Std., alle Sitzungen weg). Liefert die Sperrzeit oder 0. */
function mfaFail (u, ip) {
  const t = Date.now()
  const n = t - Number(u.mfa_fail_at || 0) > MFA_WINDOW ? 1 : Number(u.mfa_fails || 0) + 1
  if (n < MFA_MAX) { db.prepare('UPDATE users SET mfa_fails = ?, mfa_fail_at = ? WHERE id = ?').run(n, t, u.id); return 0 }
  const until = t + MFA_LOCK
  db.prepare('UPDATE users SET mfa_fails = ?, mfa_fail_at = ?, mfa_locked_until = ? WHERE id = ?').run(n, t, until, u.id)
  db.prepare('DELETE FROM sessions WHERE user_id = ?').run(u.id)
  sysLog('warn', `${u.name}: ${n} falsche Zwei-Faktor-Codes – Anmeldung 24 Std. gesperrt (zuletzt von ${String(ip || '?').slice(0, 64)})`)
  try { onMfaLock(ip, u) } catch { /* Sperre im Konto gilt trotzdem */ }
  return until
}
const mfaOk = (u) => { if (u.mfa_fails || u.mfa_locked_until) db.prepare('UPDATE users SET mfa_fails = 0, mfa_fail_at = 0, mfa_locked_until = 0 WHERE id = ?').run(u.id) }
const clearMfaLock = (name) => db.prepare('UPDATE users SET mfa_fails = 0, mfa_fail_at = 0, mfa_locked_until = 0 WHERE lower(name) = ?').run(String(name || '').toLowerCase())

/** Hebt Login-Bremse und 2FA-Sperre eines Kontos auf (Verwalter) */
export const unlockName = (name) => { clearMfaLock(name); return fails.delete('name:' + String(name || '').toLowerCase()) }
export const isLockedName = (name) => !!tooMany('name:' + String(name || '').toLowerCase()) ||
  !!mfaLockedUntil(db.prepare('SELECT mfa_locked_until FROM users WHERE lower(name) = ?').get(String(name || '').toLowerCase()))

const DUMMY = 'scrypt$16$AAAAAAAAAAAAAAAAAAAAAA==$' + Buffer.alloc(64).toString('base64')
const nextStage = (u) => u.must_change ? 'pw' : (u.totp_on ? 'mfa' : 'enroll')

export async function login (name, pw, ip, remember = true) {
  const lname = String(name || '').toLowerCase()
  if (tooMany('ip:' + ip) || tooMany('name:' + lname)) return { error: 'Zu viele Fehlversuche – bitte 15 Minuten warten.', locked: true }
  const u = db.prepare('SELECT * FROM users WHERE lower(name) = ?').get(lname)
  const ok = await verifyPassword(pw, u ? u.hash : DUMMY)
  if (!u || !ok) {
    fail('ip:' + ip); fail('name:' + lname)
    return { error: 'Benutzername oder Passwort falsch.', failed: true }
  }
  if (u.disabled) return { error: 'Dieser Zugang ist gesperrt. Bitte den Verwalter fragen.' }
  if (mfaLockedUntil(u)) return { error: mfaLockText(mfaLockedUntil(u)), locked: true }
  fails.delete('ip:' + ip); fails.delete('name:' + lname)
  const token = crypto.randomBytes(32).toString('base64url')
  const csrf = crypto.randomBytes(24).toString('base64url')
  const stage = nextStage(u)
  db.prepare('INSERT INTO sessions (token_hash, user_id, csrf, expires_at, remember, stage, ip, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
    .run(sha(token), u.id, csrf, Date.now() + STAGE_MS, remember ? 1 : 0, stage, String(ip || '').slice(0, 64), now())
  return { token, remember, stage }
}

export function sessionFor (token) {
  if (!token) return null
  const s = db.prepare('SELECT s.*, u.name, u.display, u.role, u.disabled, u.totp_on, u.must_change, u.notice FROM sessions s JOIN users u ON u.id = s.user_id WHERE token_hash = ?').get(sha(token))
  if (!s || s.expires_at < Date.now()) return null
  if (s.disabled) { db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(s.token_hash); return null }
  let stage = s.stage
  // 2FA ist Pflicht: Sitzungen von vor 2.0 bzw. nach „2FA zurücksetzen“ müssen sie erst einrichten
  if (stage === 'full' && (!s.totp_on || s.must_change)) {
    stage = s.must_change ? 'pw' : 'enroll'
    db.prepare('UPDATE sessions SET stage = ?, expires_at = ? WHERE token_hash = ?').run(stage, Date.now() + STAGE_MS, s.token_hash)
  }
  let renewed = false
  if (stage === 'full') {
    // gleitend verlängern (bei „Angemeldet bleiben“ höchstens einmal am Tag, dann wird auch das Cookie erneuert)
    if (s.remember && s.expires_at - Date.now() < (SESSION_DAYS - 1) * 864e5) {
      db.prepare('UPDATE sessions SET expires_at = ? WHERE token_hash = ?').run(Date.now() + SESSION_DAYS * 864e5, s.token_hash)
      renewed = true
    } else if (!s.remember && s.expires_at - Date.now() < SHORT_MS - 5 * 60000) {
      db.prepare('UPDATE sessions SET expires_at = ? WHERE token_hash = ?').run(Date.now() + SHORT_MS, s.token_hash)
    }
  }
  return {
    userId: s.user_id, name: s.name, display: s.display || s.name, role: s.role, admin: s.role === 'admin',
    csrf: s.csrf, tokenHash: s.token_hash, remember: !!s.remember, renewed, stage, stepupAt: s.stepup_at, notice: s.notice || ''
  }
}

/** Nächste Stufe nach erledigtem Schritt; bei „full“ gilt die normale Laufzeit (30 Tage bzw. 12 Std.) */
function advance (session) {
  const u = getUser(session.userId)
  const st = u.must_change ? 'pw' : (u.totp_on ? 'full' : 'enroll')
  const exp = st === 'full' ? Date.now() + (session.remember ? SESSION_DAYS * 864e5 : SHORT_MS) : Date.now() + STAGE_MS
  db.prepare('UPDATE sessions SET stage = ?, expires_at = ?, tries = 0, stepup_at = ? WHERE token_hash = ?')
    .run(st, exp, st === 'full' ? Date.now() : 0, session.tokenHash)
  if (st === 'full') db.prepare('UPDATE users SET last_login = ?, notice = NULL WHERE id = ?').run(now(), u.id)
  return st
}

/** Neues Passwort in der Stufe „pw“ (nach Zurücksetzen durch den Verwalter) */
export async function setOwnPassword (session, pw) {
  await changePassword(session.userId, pw, session.tokenHash)
  return advance(session)
}

/** Geheimnis für die Einrichtung (bleibt gleich, bis die Einrichtung abgeschlossen ist) */
export function enrollSecret (userId) {
  const u = getUser(userId)
  if (u.totp_on) return null
  let sec = decrypt(u.totp_secret)
  if (!sec) { sec = newSecret(); db.prepare('UPDATE users SET totp_secret = ? WHERE id = ?').run(encrypt(sec), userId) }
  return sec
}

function tooManyTries (session) {
  const n = db.prepare('UPDATE sessions SET tries = tries + 1 WHERE token_hash = ? RETURNING tries').get(session.tokenHash)
  if (n && n.tries >= 5) { db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(session.tokenHash); return true }
  return false
}

/** Einrichtung abschließen: erster Code aus der App → 2FA an, Notfallcodes werden einmal angezeigt */
export function finishEnroll (session, code, { ip = '' } = {}) {
  const u = getUser(session.userId)
  if (mfaLockedUntil(u)) { db.prepare('DELETE FROM sessions WHERE user_id = ?').run(u.id); return { error: 'locked', until: mfaLockedUntil(u) } }
  const sec = decrypt(u.totp_secret)
  const step = sec ? verifyTotp(sec, code, 0) : 0
  if (!step) {
    const until = mfaFail(u, ip)
    if (until) return { error: 'locked', until }
    return { error: tooManyTries(session) ? 'gone' : 'Der Code stimmt nicht – bitte den aktuellen Code aus der App eingeben (Uhrzeit am Handy prüfen).' }
  }
  mfaOk(u)
  const rc = newRecoveryCodes()
  db.prepare('UPDATE users SET totp_on = 1, totp_last = ?, recovery = ? WHERE id = ?').run(step, JSON.stringify(rc.hashes), u.id)
  sysLog('info', `${u.name}: Zwei-Faktor-Anmeldung eingerichtet`)
  advance(session)
  return { codes: rc.codes }
}

/** Code (oder Notfallcode) prüfen – für die Anmeldung (Stufe mfa) und für die Bestätigung vor Verwaltungsaufgaben */
export function checkSecondFactor (session, code, { stepup = false, ip = '' } = {}) {
  const u = getUser(session.userId)
  if (mfaLockedUntil(u)) { db.prepare('DELETE FROM sessions WHERE user_id = ?').run(u.id); return { error: 'locked', until: mfaLockedUntil(u) } }
  const sec = decrypt(u.totp_secret)
  let how = ''
  const step = sec && u.totp_on ? verifyTotp(sec, code, u.totp_last) : 0
  if (step) { db.prepare('UPDATE users SET totp_last = ? WHERE id = ?').run(step, u.id); how = 'app' } else {
    let list = []
    try { list = JSON.parse(u.recovery || '[]') } catch { list = [] }
    const rest = useRecoveryCode(list, code)
    if (rest) { db.prepare('UPDATE users SET recovery = ? WHERE id = ?').run(JSON.stringify(rest), u.id); how = 'notfallcode'; sysLog('warn', `${u.name}: mit Notfallcode angemeldet (${rest.length} übrig)`) }
  }
  if (!how) {
    const until = mfaFail(u, ip)
    if (until) return { error: 'locked', until }
    return { error: tooManyTries(session) ? 'gone' : 'Der Code stimmt nicht.' }
  }
  mfaOk(u)
  if (stepup) db.prepare('UPDATE sessions SET stepup_at = ?, tries = 0 WHERE token_hash = ?').run(Date.now(), session.tokenHash)
  else advance(session)
  return { ok: true, how, left: how === 'notfallcode' ? JSON.parse(getUser(u.id).recovery || '[]').length : null }
}
export const stepupValid = (session) => session && Date.now() - Number(session.stepupAt || 0) < STEPUP_MS

/** Neue Notfallcodes (alte werden ungültig) */
export function regenerateRecovery (userId) {
  const rc = newRecoveryCodes()
  db.prepare('UPDATE users SET recovery = ? WHERE id = ?').run(JSON.stringify(rc.hashes), userId)
  return rc.codes
}
export const recoveryLeft = (userId) => { try { return JSON.parse(getUser(userId).recovery || '[]').length } catch { return 0 } }

export function logout (token) {
  if (token) db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(sha(token))
}

// ---------- Verwalter: Zugang wiederherstellen ----------
const ABC = 'abcdefghjkmnpqrstuvwxyz23456789'
export const oneTimePassword = () => Array.from({ length: 3 }, () => Array.from(crypto.randomBytes(4), b => ABC[b % ABC.length]).join('')).join('-')

export async function adminResetPassword (userId, by) {
  const u = getUser(userId)
  if (!u) throw new Error('Nutzer nicht gefunden.')
  const pw = oneTimePassword()
  db.prepare('UPDATE users SET hash = ?, must_change = 1, notice = ? WHERE id = ?').run(await hashPassword(pw), 'Dein Passwort wurde vom Verwalter zurückgesetzt. Bitte vergib jetzt ein eigenes.', u.id)
  db.prepare('DELETE FROM sessions WHERE user_id = ?').run(u.id)
  unlockName(u.name)
  sysLog('warn', `Verwalter ${by}: Passwort von „${u.name}“ zurückgesetzt`)
  return pw
}
export function adminReset2fa (userId, by) {
  const u = getUser(userId)
  if (!u) throw new Error('Nutzer nicht gefunden.')
  db.prepare('UPDATE users SET totp_on = 0, totp_secret = NULL, recovery = NULL, totp_last = 0, mfa_fails = 0, mfa_fail_at = 0, mfa_locked_until = 0, notice = ? WHERE id = ?')
    .run('Deine Zwei-Faktor-Anmeldung wurde vom Verwalter zurückgesetzt. Bitte richte sie jetzt neu ein.', u.id)
  db.prepare('DELETE FROM sessions WHERE user_id = ?').run(u.id)
  sysLog('warn', `Verwalter ${by}: Zwei-Faktor-Anmeldung von „${u.name}“ zurückgesetzt`)
}
export function adminLogoutAll (userId, by, exceptTokenHash = null) {
  const u = getUser(userId)
  if (!u) throw new Error('Nutzer nicht gefunden.')
  const r = exceptTokenHash
    ? db.prepare('DELETE FROM sessions WHERE user_id = ? AND token_hash <> ?').run(u.id, exceptTokenHash)
    : db.prepare('DELETE FROM sessions WHERE user_id = ?').run(u.id)
  sysLog('warn', `Verwalter ${by}: „${u.name}“ auf allen Geräten abgemeldet (${r.changes} Sitzungen)`)
  return Number(r.changes || 0)
}
export function adminSetDisabled (userId, on, by) {
  const u = getUser(userId)
  if (!u) throw new Error('Nutzer nicht gefunden.')
  if (on && u.role === 'admin' && db.prepare("SELECT COUNT(*) n FROM users WHERE role = 'admin' AND disabled = 0").get().n <= 1) throw new Error('Der letzte Verwalter kann nicht gesperrt werden.')
  db.prepare('UPDATE users SET disabled = ? WHERE id = ?').run(on ? 1 : 0, u.id)
  if (on) db.prepare('DELETE FROM sessions WHERE user_id = ?').run(u.id)
  else unlockName(u.name)
  sysLog('warn', `Verwalter ${by}: „${u.name}“ ${on ? 'gesperrt' : 'entsperrt'}`)
}
export function adminSetUser (userId, { display, role, features }, by) {
  const u = getUser(userId)
  if (!u) throw new Error('Nutzer nicht gefunden.')
  const newRole = role === 'admin' ? 'admin' : 'user'
  if (u.role === 'admin' && newRole !== 'admin' && db.prepare("SELECT COUNT(*) n FROM users WHERE role = 'admin' AND disabled = 0").get().n <= 1) throw new Error('Es muss mindestens einen Verwalter geben.')
  db.prepare('UPDATE users SET display = ?, role = ?, features = ? WHERE id = ?').run(String(display || '').slice(0, 60), newRole, JSON.stringify(features), u.id)
  sysLog('info', `Verwalter ${by}: Einstellungen von „${u.name}“ geändert`)
}
export function adminDeleteUser (userId, by) {
  const u = getUser(userId)
  if (!u) throw new Error('Nutzer nicht gefunden.')
  if (!u.data) throw new Error('Dieses Konto nutzt die Haupt-Datenbank und kann nicht gelöscht werden.')
  if (u.role === 'admin' && db.prepare("SELECT COUNT(*) n FROM users WHERE role = 'admin'").get().n <= 1) throw new Error('Der letzte Verwalter kann nicht gelöscht werden.')
  db.prepare('DELETE FROM sessions WHERE user_id = ?').run(u.id)
  db.prepare('DELETE FROM users WHERE id = ?').run(u.id)
  dropUserData(u)
  sysLog('warn', `Verwalter ${by}: Nutzer „${u.name}“ mit allen Daten gelöscht`)
}
