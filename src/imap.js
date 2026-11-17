// IMAP-Zugriff (imapflow). Liest nur Kopfzeilen und den Anfang des Textes, verschiebt Mails, legt Ordner an.
import crypto from 'node:crypto'
import { ImapFlow } from 'imapflow'
import { simpleParser } from 'mailparser'
import { accountPassword } from './accounts.js'

const READ_BYTES = 96 * 1024   // so viel von jeder Mail wird gelesen (Anhänge nicht)
const SNIPPET = 1500

export function connect (acc) {
  if (!acc || !acc.host || !acc.user) throw new Error('Postfach ist nicht vollständig eingerichtet (Einstellungen → Postfächer).')
  const pass = accountPassword(acc)
  if (!pass) throw new Error(`Passwort für ${acc.user} fehlt (Einstellungen → Postfächer).`)
  return new ImapFlow({
    host: acc.host, port: Number(acc.port) || 993, secure: !!acc.secure,
    auth: { user: acc.user, pass },
    logger: false,
    tls: acc.allow_self_signed ? { rejectUnauthorized: false } : undefined,
    connectionTimeout: 30000, greetingTimeout: 20000, socketTimeout: 5 * 60000
  })
}

export async function withClient (acc, fn) {
  const client = connect(acc)
  client.on('error', () => {}) // Fehler kommen über die awaits
  await client.connect()
  try { return await fn(client) } finally { await client.logout().catch(() => client.close()) }
}

// Pfad als Teile – imapflow setzt Trennzeichen und Namensraum (z. B. „INBOX.“) selbst
export function categoryPath (cfg, cat) {
  return [cfg.root || 'Sortiert', cat.name]
}

export function pathString (client, parts) {
  if (!Array.isArray(parts)) return parts
  const ns = client.namespace || {}
  const p = parts.join(ns.delimiter || '/')
  return ns.prefix && !p.startsWith(ns.prefix) ? ns.prefix + p : p
}

export async function ensureFolders (client, cfg, cats) {
  const existing = new Set((await client.list()).map(b => b.path))
  const created = []
  const wanted = [[cfg.root || 'Sortiert'], ...cats.map(c => categoryPath(cfg, c))]
  for (const parts of wanted) {
    const p = pathString(client, parts)
    if (existing.has(p)) continue
    await client.mailboxCreate(parts)
    await client.mailboxSubscribe(p).catch(() => {}) // Outlook zeigt oft nur abonnierte Ordner
    existing.add(p)
    created.push(p)
  }
  return created
}

export async function listFolders (client) {
  return (await client.list()).map(b => b.path)
}

function addrOf (env, key = 'from') {
  const a = (env && env[key] && env[key][0]) || {}
  return { addr: String(a.address || '').toLowerCase(), name: String(a.name || '') }
}

function attachmentNames (node, out = []) {
  if (!node) return out
  const fn = (node.dispositionParameters && node.dispositionParameters.filename) || (node.parameters && node.parameters.name)
  if (fn) out.push(String(fn).slice(0, 120))
  for (const c of node.childNodes || []) attachmentNames(c, out)
  return out
}

function cleanText (s) {
  return String(s || '')
    .replace(/ /g, ' ')
    .replace(/[​-‏‪-‮⁠-⁯﻿]/g, '')
    .replace(/[ \t]+/g, ' ')
    .replace(/\n\s*\n+/g, '\n')
    .trim()
}

export function synthMsgId (from, date, subject) {
  return '<sortierer-' + crypto.createHash('sha1').update(`${from}|${date}|${subject}`).digest('hex') + '@lokal>'
}

// Mails lesen: UIDs → Kopf, Ausschnitt, Hinweise (Newsletter-Kopfzeilen, Anhänge)
export async function readMessages (client, uids) {
  const out = []
  if (!uids.length) return out
  const msgs = await client.fetchAll(uids, {
    uid: true, envelope: true, bodyStructure: true, internalDate: true,
    headers: ['list-unsubscribe', 'list-id', 'precedence', 'auto-submitted', 'x-auto-response-suppress'],
    source: { start: 0, maxLength: READ_BYTES }
  }, { uid: true })
  for (const m of msgs) {
    const from = addrOf(m.envelope)
    const subject = String((m.envelope && m.envelope.subject) || '').slice(0, 300)
    const date = (m.envelope && m.envelope.date) || m.internalDate
    const dateIso = date ? new Date(date).toISOString() : ''
    let text = ''
    try {
      const parsed = await simpleParser(m.source || Buffer.alloc(0), { skipImageLinks: true, skipTextToHtml: true })
      text = parsed.text || (parsed.html ? String(parsed.html).replace(/<style[\s\S]*?<\/style>|<script[\s\S]*?<\/script>/gi, ' ').replace(/<[^>]+>/g, ' ').replace(/&nbsp;/g, ' ') : '')
    } catch { text = '' }
    const headers = String(m.headers || '').toLowerCase()
    const hints = []
    if (headers.includes('list-unsubscribe')) hints.push('hat Abmelde-Link (List-Unsubscribe)')
    if (headers.includes('list-id')) hints.push('kommt über eine Verteilerliste (List-Id)')
    if (/precedence:\s*(bulk|list|junk)/.test(headers)) hints.push('Massenversand (Precedence bulk)')
    if (/auto-submitted:\s*auto-/.test(headers)) hints.push('automatisch erzeugt (Auto-Submitted)')
    if (/^(no-?reply|do-?not-?reply|noreply|mailer-daemon|notifications?|info@|news(letter)?@)/.test(from.addr)) hints.push('Absender ist eine automatische Adresse')
    const att = attachmentNames(m.bodyStructure).filter(n => !/^(image|outlook-)\S*\.(png|gif|jpe?g)$/i.test(n)) // eingebettete Signaturbilder weglassen
    if (att.length) hints.push('Anhänge: ' + att.slice(0, 6).join(', '))
    const msgid = (m.envelope && m.envelope.messageId) || synthMsgId(from.addr, dateIso, subject)
    out.push({
      uid: m.uid,
      msgid: String(msgid).slice(0, 500),
      from_addr: from.addr,
      from_name: from.name.slice(0, 200),
      domain: from.addr.split('@')[1] || '',
      subject,
      date: dateIso,
      snippet: cleanText(text).slice(0, SNIPPET),
      hints: hints.join('; '),
      attachments: att
    })
  }
  return out
}

// Nur Message-IDs (für Ordner-Beobachtung, schnell)
export async function readIds (client, uids) {
  if (!uids.length) return []
  const msgs = await client.fetchAll(uids, { uid: true, envelope: true }, { uid: true })
  return msgs.map(m => {
    const from = addrOf(m.envelope)
    const subject = String((m.envelope && m.envelope.subject) || '').slice(0, 300)
    const dateIso = m.envelope && m.envelope.date ? new Date(m.envelope.date).toISOString() : ''
    return { uid: m.uid, msgid: (m.envelope && m.envelope.messageId) || synthMsgId(from.addr, dateIso, subject) }
  })
}

// Verschieben; liefert die neue UID im Zielordner (falls der Server sie meldet)
export async function moveMessage (client, uid, destPath) {
  const r = await client.messageMove(String(uid), destPath, { uid: true })
  if (!r) throw new Error('Verschieben fehlgeschlagen')
  const newUid = r.uidMap && r.uidMap.get(Number(uid))
  return newUid || null
}

export async function findByMsgId (client, msgid) {
  if (!msgid || msgid.startsWith('<sortierer-')) return []
  const r = await client.search({ header: { 'message-id': msgid } }, { uid: true })
  return Array.isArray(r) ? r : []
}

// Ordner (auch verschachtelt) anlegen und abonnieren, falls nötig. parts = ['Rechnungen', '2026', '2026-11']
export async function ensurePath (client, parts, known) {
  const have = known || new Set((await client.list()).map(b => b.path))
  for (let i = 1; i <= parts.length; i++) {
    const p = pathString(client, parts.slice(0, i))
    if (have.has(p)) continue
    await client.mailboxCreate(parts.slice(0, i))
    await client.mailboxSubscribe(p).catch(() => {})
    have.add(p)
  }
  return pathString(client, parts)
}

// Ganze Mail (mit Anhängen) laden – nur für Rechnungen
export async function fetchSource (client, uid) {
  const m = await client.fetchOne(String(uid), { source: true }, { uid: true })
  if (!m || !m.source) throw new Error('Mail nicht mehr vorhanden')
  return m.source
}

export async function appendMessage (client, path, source, flags) {
  const r = await client.append(path, source, flags || [])
  return (r && r.uid) || null
}

export async function setFlag (client, path, uid, flag, on) {
  if (!uid) return
  const lock = await client.getMailboxLock(path)
  try {
    if (on) await client.messageFlagsAdd(String(uid), [flag], { uid: true })
    else await client.messageFlagsRemove(String(uid), [flag], { uid: true })
  } finally { lock.release() }
}
