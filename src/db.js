// Datenbank (eingebautes node:sqlite) – alles liegt unter DATA_DIR, nichts verlässt den Server.
// Mehrere Nutzer (ab 2.0): Die Haupt-Datenbank (mail-sortierer.sqlite) hält Benutzer, Sitzungen, Angriffsschutz und
// globale Einstellungen (Ollama, Lizenz) – und die Daten des ersten Kontos (Verwalter, Bestand vor 2.0).
// Jeder weitere Nutzer bekommt eine eigene Datenbank unter DATA_DIR/nutzer/<id>/ (Postfächer, Mails, Regeln, Rechnungen …).
// Welche Datenbank gerade gilt, steht im Anfrage-/Durchlauf-Kontext (AsyncLocalStorage) – der Rest des Codes nutzt einfach `db`.
import { DatabaseSync } from 'node:sqlite'
import { AsyncLocalStorage } from 'node:async_hooks'
import fs from 'node:fs'
import path from 'node:path'

export const DATA_DIR = process.env.DATA_DIR || path.resolve('data')
fs.mkdirSync(DATA_DIR, { recursive: true })

function initSchema (db) {
db.exec(`
CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, hash TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL, csrf TEXT NOT NULL, expires_at INTEGER NOT NULL
);

-- Postfächer (Passwort verschlüsselt in kv 'secrets' unter imap:<id>)
CREATE TABLE IF NOT EXISTS accounts (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL, host TEXT NOT NULL, port INTEGER NOT NULL DEFAULT 993, secure INTEGER NOT NULL DEFAULT 1,
  user TEXT NOT NULL, allow_self_signed INTEGER NOT NULL DEFAULT 0,
  enabled INTEGER NOT NULL DEFAULT 1, mode TEXT NOT NULL DEFAULT 'probe',
  created_at TEXT NOT NULL
);

-- Jede Mail, die der Sortierer gesehen hat (Schlüssel = Postfach + Message-ID)
CREATE TABLE IF NOT EXISTS mails (
  id INTEGER PRIMARY KEY,
  account_id INTEGER NOT NULL DEFAULT 1,
  msgid TEXT NOT NULL,
  from_addr TEXT, from_name TEXT, domain TEXT, subject TEXT, date TEXT,
  snippet TEXT,
  hints TEXT,
  folder TEXT,            -- Ordner, in dem die Mail zuletzt gesehen wurde
  uid INTEGER, uidvalidity TEXT,
  decision TEXT,          -- Kategorie-ID oder 'inbox'
  source TEXT,            -- rule | contact | ki | own | correction | manual
  confidence INTEGER, reason TEXT,
  status TEXT NOT NULL,   -- planned | moved | kept | undone | error | gone
  error TEXT,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL, moved_at TEXT,
  UNIQUE(account_id, msgid)
);

-- Rechnungen (aus Mails und Scans). Datei liegt unter DATA_DIR/belege/
CREATE TABLE IF NOT EXISTS invoices (
  id INTEGER PRIMARY KEY,
  source TEXT NOT NULL,          -- mail | scan
  account_id INTEGER, mail_id INTEGER, msgid TEXT,
  from_addr TEXT, subject TEXT,
  supplier TEXT, number TEXT, inv_date TEXT, amount REAL, currency TEXT,
  einvoice TEXT,                 -- zugferd | xrechnung | ''
  file TEXT, file_name TEXT, file_hash TEXT, xml_file TEXT,
  dedupe TEXT,
  folder TEXT, uid INTEGER, same_message INTEGER NOT NULL DEFAULT 0,
  suggestion TEXT, hint TEXT,    -- business | private, kurzer Grund
  status TEXT NOT NULL,          -- open | sent | private | noinvoice | duplicate | error
  lexware_id TEXT, error TEXT,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL, decided_at TEXT
);
CREATE INDEX IF NOT EXISTS invoices_status ON invoices(status);
CREATE INDEX IF NOT EXISTS invoices_dedupe ON invoices(dedupe);
CREATE INDEX IF NOT EXISTS invoices_hash ON invoices(file_hash);

-- Regeln: Absender/Domain -> Ziel. state suggest = Vorschlag, active = gilt, off = aus (z. B. gemischter Absender)
CREATE TABLE IF NOT EXISTS rules (
  id INTEGER PRIMARY KEY,
  kind TEXT NOT NULL, value TEXT NOT NULL, target TEXT NOT NULL,
  state TEXT NOT NULL, hits INTEGER NOT NULL DEFAULT 0, conflicts INTEGER NOT NULL DEFAULT 0,
  origin TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
  UNIQUE(kind, value)
);

-- Beispiele aus Korrekturen – bekommt die KI bei ähnlichen Mails mit
CREATE TABLE IF NOT EXISTS examples (
  id INTEGER PRIMARY KEY,
  msgid TEXT, from_addr TEXT, domain TEXT, subject TEXT, snippet TEXT,
  target TEXT NOT NULL, previous TEXT, origin TEXT, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS examples_from ON examples(from_addr);
CREATE INDEX IF NOT EXISTS examples_domain ON examples(domain);

-- Bekannte Kontakte (z. B. Kunden-/Lieferantenliste aus Vedly)
CREATE TABLE IF NOT EXISTS contacts (
  email TEXT PRIMARY KEY, name TEXT, target TEXT NOT NULL, created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS log (
  id INTEGER PRIMARY KEY, at TEXT NOT NULL, level TEXT NOT NULL, text TEXT NOT NULL
);
`)

// Umzug von 1.0 (ein Postfach, msgid allein eindeutig) auf mehrere Postfächer
if (!db.prepare('PRAGMA table_info(mails)').all().some(c => c.name === 'account_id')) {
  db.exec(`BEGIN;
    ALTER TABLE mails RENAME TO mails_alt;
    CREATE TABLE mails (
      id INTEGER PRIMARY KEY, account_id INTEGER NOT NULL DEFAULT 1, msgid TEXT NOT NULL,
      from_addr TEXT, from_name TEXT, domain TEXT, subject TEXT, date TEXT, snippet TEXT, hints TEXT,
      folder TEXT, uid INTEGER, uidvalidity TEXT, decision TEXT, source TEXT, confidence INTEGER, reason TEXT,
      status TEXT NOT NULL, error TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, moved_at TEXT,
      UNIQUE(account_id, msgid));
    INSERT INTO mails (id, account_id, msgid, from_addr, from_name, domain, subject, date, snippet, hints, folder, uid, uidvalidity,
      decision, source, confidence, reason, status, error, created_at, updated_at, moved_at)
      SELECT id, 1, msgid, from_addr, from_name, domain, subject, date, snippet, hints, folder, uid, uidvalidity,
      decision, source, confidence, reason, status, error, created_at, updated_at, moved_at FROM mails_alt;
    DROP TABLE mails_alt;
    COMMIT;`)
}
// Spalten, die später dazugekommen sind
function addColumn (table, col, type) {
  if (!db.prepare(`PRAGMA table_info(${table})`).all().some(c => c.name === col)) db.exec(`ALTER TABLE ${table} ADD COLUMN ${col} ${type}`)
}
addColumn('mails', 'risk', 'INTEGER')          // Punktzahl der Sicherheitsprüfung
addColumn('mails', 'risk_reasons', 'TEXT')     // Gründe (JSON)
addColumn('invoices', 'brand', 'TEXT')         // eigene Firma/Marke, an die die Rechnung ging
addColumn('invoices', 'risk', 'TEXT')
addColumn('invoices', 'content', 'TEXT')       // worum es geht (kurz)
addColumn('invoices', 'text_snippet', 'TEXT')  // Textanfang des Belegs – für Lernbeispiele
// Ab 2.0: mehrere Nutzer, 2FA, Sitzungs-Stufen
addColumn('users', 'role', "TEXT NOT NULL DEFAULT 'user'")   // admin | user
addColumn('users', 'display', 'TEXT')                         // Anzeigename
addColumn('users', 'data', "TEXT NOT NULL DEFAULT ''")        // '' = Haupt-Datenbank, sonst nutzer/<id>
addColumn('users', 'features', 'TEXT')                        // JSON: welche Bereiche dieser Nutzer hat
addColumn('users', 'totp_secret', 'TEXT')                     // verschlüsselt (secrets.js)
addColumn('users', 'totp_on', 'INTEGER NOT NULL DEFAULT 0')
addColumn('users', 'totp_last', 'INTEGER NOT NULL DEFAULT 0') // zuletzt benutzter Zeitschritt (kein zweites Mal)
addColumn('users', 'recovery', 'TEXT')                        // JSON: SHA-256 der Notfallcodes
addColumn('users', 'must_change', 'INTEGER NOT NULL DEFAULT 0')
addColumn('users', 'disabled', 'INTEGER NOT NULL DEFAULT 0')
addColumn('users', 'notice', 'TEXT')                          // Hinweis bei der nächsten Anmeldung
addColumn('users', 'last_login', 'TEXT')
addColumn('sessions', 'remember', 'INTEGER NOT NULL DEFAULT 1')
addColumn('sessions', 'stage', "TEXT NOT NULL DEFAULT 'full'") // pw | enroll | mfa | full
addColumn('sessions', 'stepup_at', 'INTEGER NOT NULL DEFAULT 0')
addColumn('sessions', 'tries', 'INTEGER NOT NULL DEFAULT 0')
addColumn('sessions', 'ip', 'TEXT')
addColumn('sessions', 'created_at', 'TEXT')
// Webmail: Postausgang je Postfach
addColumn('accounts', 'smtp_host', 'TEXT')
addColumn('accounts', 'smtp_port', 'INTEGER')
addColumn('accounts', 'smtp_secure', 'INTEGER NOT NULL DEFAULT 1')
addColumn('accounts', 'smtp_user', 'TEXT')
addColumn('accounts', 'smtp_same', 'INTEGER NOT NULL DEFAULT 1')  // gleiches Passwort wie IMAP
addColumn('accounts', 'from_name', 'TEXT')
addColumn('accounts', 'sig_new', 'INTEGER')     // Standard-Signatur neue Mail
addColumn('accounts', 'sig_reply', 'INTEGER')   // Standard-Signatur Antwort/Weiterleitung
db.exec(`CREATE TABLE IF NOT EXISTS signatures (
  id INTEGER PRIMARY KEY, name TEXT NOT NULL, html TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS image_ok (sender TEXT PRIMARY KEY, created_at TEXT NOT NULL);`)

// Gelerntes aus Rechnungs-Prüfungen (Angaben korrigiert, Lexware/Privat/Keine Rechnung)
db.exec(`CREATE TABLE IF NOT EXISTS inv_examples (
  id INTEGER PRIMARY KEY, invoice_id INTEGER, from_addr TEXT, domain TEXT, supplier TEXT, brand TEXT, number TEXT, inv_date TEXT,
  amount REAL, content TEXT, decision TEXT NOT NULL, snippet TEXT, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS inv_examples_from ON inv_examples(from_addr);
CREATE INDEX IF NOT EXISTS inv_examples_domain ON inv_examples(domain);`)          // Sicherheitsbefund des Belegs (JSON) – gesperrt, wenn gesetzt

db.exec(`
CREATE INDEX IF NOT EXISTS mails_status ON mails(status);
CREATE INDEX IF NOT EXISTS mails_from ON mails(from_addr);
CREATE INDEX IF NOT EXISTS mails_folder_uid ON mails(account_id, folder, uidvalidity, uid);
`)

}

function openDb (file) {
  const d = new DatabaseSync(file)
  d.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;')
  initSchema(d)
  return d
}

// Haupt-Datenbank: Benutzer, Sitzungen, globale Einstellungen + Daten des ersten Kontos
export const sysdb = openDb(path.join(DATA_DIR, 'mail-sortierer.sqlite'))

const store = new AsyncLocalStorage()
const userDbs = new Map()

/** Ordner eines Nutzers ('' = Haupt-Datenbank / DATA_DIR) */
function dirFor (user) {
  const rel = user && user.data ? String(user.data) : ''
  if (!rel) return DATA_DIR
  if (!/^nutzer\/\d{1,9}$/.test(rel)) throw new Error('Ungültiger Datenordner')
  return path.join(DATA_DIR, rel)
}
function dbFor (user) {
  const rel = user && user.data ? String(user.data) : ''
  if (!rel) return sysdb
  if (!userDbs.has(rel)) {
    const dir = dirFor(user)
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 })
    userDbs.set(rel, openDb(path.join(dir, 'daten.sqlite')))
  }
  return userDbs.get(rel)
}

/** fn im Kontext dieses Nutzers ausführen (eigene Datenbank, eigener Belege-Ordner) */
export function withUser (user, fn) {
  return store.run({ user, db: dbFor(user), dir: dirFor(user) }, fn)
}
export const currentUser = () => (store.getStore() || {}).user || null
export const dataDir = () => (store.getStore() || {}).dir || DATA_DIR
const current = () => (store.getStore() || {}).db || sysdb

// `db` zeigt immer auf die Datenbank des aktuellen Nutzers (ohne Kontext: Haupt-Datenbank)
export const db = new Proxy({}, {
  get (_, k) {
    const d = current()
    const v = d[k]
    return typeof v === 'function' ? v.bind(d) : v
  }
})

/** Datenbank eines Nutzers schließen und Ordner löschen (Nutzer entfernt) */
export function dropUserData (user) {
  const rel = user && user.data ? String(user.data) : ''
  if (!rel) return
  const d = userDbs.get(rel)
  if (d) { try { d.close() } catch { /* egal */ } userDbs.delete(rel) }
  fs.rmSync(dirFor(user), { recursive: true, force: true })
}

export const now = () => new Date().toISOString()

export function kvGet (k, fallback = null) {
  const row = db.prepare('SELECT v FROM kv WHERE k = ?').get(k)
  if (!row) return fallback
  try { return JSON.parse(row.v) } catch { return fallback }
}

export function kvSet (k, v) {
  db.prepare('INSERT INTO kv (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v').run(k, JSON.stringify(v))
}

export function log (level, text) {
  const t = String(text).slice(0, 2000)
  db.prepare('INSERT INTO log (at, level, text) VALUES (?, ?, ?)').run(now(), level, t)
  if (level === 'error') console.error('[mail-sortierer]', t)
  else console.log('[mail-sortierer]', t)
}

// Protokoll und Beispiele nicht endlos wachsen lassen
export function prune () {
  db.prepare('DELETE FROM log WHERE id NOT IN (SELECT id FROM log ORDER BY id DESC LIMIT 3000)').run()
  db.prepare('DELETE FROM examples WHERE id NOT IN (SELECT id FROM examples ORDER BY id DESC LIMIT 3000)').run()
  sysdb.prepare('DELETE FROM sessions WHERE expires_at < ?').run(Date.now())
}

export function tx (fn) {
  db.exec('BEGIN')
  try { const r = fn(); db.exec('COMMIT'); return r } catch (e) { db.exec('ROLLBACK'); throw e }
}

// Globale Werte (immer Haupt-Datenbank): Lizenz, Angriffsschutz, Ollama …
export function sysGet (k, fallback = null) {
  const row = sysdb.prepare('SELECT v FROM kv WHERE k = ?').get(k)
  if (!row) return fallback
  try { return JSON.parse(row.v) } catch { return fallback }
}
export function sysSet (k, v) {
  sysdb.prepare('INSERT INTO kv (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v').run(k, JSON.stringify(v))
}
export function sysLog (level, text) {
  const t = String(text).slice(0, 2000)
  sysdb.prepare('INSERT INTO log (at, level, text) VALUES (?, ?, ?)').run(now(), level, t)
  console.log('[mail-sortierer]', t)
}
