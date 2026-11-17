// Datenbank (eingebautes node:sqlite) – alles liegt unter DATA_DIR, nichts verlässt den Server.
import { DatabaseSync } from 'node:sqlite'
import fs from 'node:fs'
import path from 'node:path'

export const DATA_DIR = process.env.DATA_DIR || path.resolve('data')
fs.mkdirSync(DATA_DIR, { recursive: true })

export const db = new DatabaseSync(path.join(DATA_DIR, 'mail-sortierer.sqlite'))
db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;')

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
addColumn('invoices', 'brand', 'TEXT')         // Firma/Marke (z. B. Flexisticker, 3dbymicha)
addColumn('invoices', 'risk', 'TEXT')
addColumn('invoices', 'content', 'TEXT')       // worum es geht (kurz)          // Sicherheitsbefund des Belegs (JSON) – gesperrt, wenn gesetzt

db.exec(`
CREATE INDEX IF NOT EXISTS mails_status ON mails(status);
CREATE INDEX IF NOT EXISTS mails_from ON mails(from_addr);
CREATE INDEX IF NOT EXISTS mails_folder_uid ON mails(account_id, folder, uidvalidity, uid);
`)

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
  db.prepare('DELETE FROM sessions WHERE expires_at < ?').run(Date.now())
}

export function tx (fn) {
  db.exec('BEGIN')
  try { const r = fn(); db.exec('COMMIT'); return r } catch (e) { db.exec('ROLLBACK'); throw e }
}
