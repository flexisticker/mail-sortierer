// Webmail: Ordner, Mailliste, Lesen, Anhänge, Markieren/Verschieben/Löschen – direkt per IMAP, nichts wird kopiert.
// Verbindungen werden je Nutzer und Postfach kurz offen gehalten (schneller beim Blättern) und nacheinander benutzt.
import { simpleParser } from 'mailparser'
import sanitizeHtml from 'sanitize-html'
import { connect, ensurePath } from './imap.js'
import { currentUser, db, now } from './db.js'
import { scanAttachment, phishCheck, brandList } from './security.js'
import { getConfig } from './config.js'
import { isTrusted, isKnown } from './learn.js'
import { findTrash } from './cleanup.js'

const IDLE_MS = 3 * 60 * 1000
const MAX_SOURCE = 40 * 1024 * 1024
const pool = new Map() // key → { client, busy: Promise, timer }

async function getClient (acc) {
  const key = `${(currentUser() || {}).id || 0}:${acc.id}`
  let e = pool.get(key)
  if (e && e.client.usable) { clearTimeout(e.timer) } else {
    if (e) { try { e.client.close() } catch { /* weg */ } }
    const client = connect(acc)
    client.on('error', () => {})
    client.on('close', () => { if (pool.get(key) && pool.get(key).client === client) pool.delete(key) })
    await client.connect()
    e = { client, busy: Promise.resolve(), timer: null }
    pool.set(key, e)
  }
  e.timer = setTimeout(() => { pool.delete(key); e.client.logout().catch(() => e.client.close()) }, IDLE_MS)
  e.timer.unref?.()
  return e
}

/** fn(client) mit der Verbindung dieses Postfachs ausführen – nacheinander, nie parallel auf derselben Verbindung */
export async function withMail (acc, fn) {
  const e = await getClient(acc)
  const run = e.busy.then(() => fn(e.client))
  e.busy = run.catch(() => {})
  return run
}
export function dropConnection (acc) {
  const key = `${(currentUser() || {}).id || 0}:${acc.id}`
  const e = pool.get(key)
  if (e) { pool.delete(key); clearTimeout(e.timer); e.client.logout().catch(() => e.client.close()) }
}

// ---------- Ordner ----------
const SPECIAL = { '\\Inbox': 'Posteingang', '\\Sent': 'Gesendet', '\\Drafts': 'Entwürfe', '\\Trash': 'Papierkorb', '\\Junk': 'Junk', '\\Archive': 'Archiv' }
const ORDER = ['\\Inbox', '\\Drafts', '\\Sent', '\\Archive', '\\Junk', '\\Trash']

export async function listFolders (acc) {
  return withMail(acc, async (client) => {
    const list = await client.list({ statusQuery: { messages: true, unseen: true } })
    const out = list.filter(b => !(b.flags && (b.flags.has('\\Noselect') || b.flags.has('\\NonExistent')))).map(b => {
      const special = b.path === 'INBOX' ? '\\Inbox' : b.specialUse || ''
      const depth = b.path === 'INBOX' ? 0 : b.path.split(b.delimiter || '/').length - 1 - (b.path.startsWith('INBOX' + (b.delimiter || '/')) ? 1 : 0)
      return { path: b.path, name: SPECIAL[special] || b.name, special, depth: Math.max(0, depth), unseen: (b.status && b.status.unseen) || 0, messages: (b.status && b.status.messages) || 0, delimiter: b.delimiter || '/' }
    })
    out.sort((a, b) => {
      const ia = ORDER.indexOf(a.special); const ib = ORDER.indexOf(b.special)
      if (ia !== -1 || ib !== -1) return (ia === -1 ? 99 : ia) - (ib === -1 ? 99 : ib)
      return a.path.localeCompare(b.path, 'de')
    })
    return out
  })
}
export async function folderExists (acc, path) {
  return (await listFolders(acc)).some(f => f.path === path)
}
export async function specialFolder (acc, use) {
  const list = await listFolders(acc)
  return (list.find(f => f.special === use) || {}).path || null
}

// ---------- Liste ----------
const addr = (a) => a && a[0] ? { name: a[0].name || '', address: (a[0].address || '').toLowerCase() } : { name: '', address: '' }
const hasAttachment = (node) => {
  if (!node) return false
  const disp = String(node.disposition || '').toLowerCase()
  if (disp === 'attachment') return true
  if (disp === 'inline' && !/^image\//.test(node.type || '') && node.dispositionParameters && node.dispositionParameters.filename) return true
  return (node.childNodes || []).some(hasAttachment)
}

export async function listMessages (acc, folder, { page = 1, per = 50, q = '' } = {}) {
  return withMail(acc, async (client) => {
    const lock = await client.getMailboxLock(folder)
    try {
      const mb = client.mailbox
      let uids = null
      let total = mb.exists
      if (q) {
        const found = (await client.search({ or: [{ subject: q }, { from: q }, { to: q }, { body: q }] }, { uid: true })) || []
        uids = found.sort((a, b) => b - a)
        total = uids.length
      }
      if (!total) return { total: 0, items: [], uidValidity: String(mb.uidValidity) }
      let range; let byUid = false
      if (uids) { range = uids.slice((page - 1) * per, page * per); byUid = true; if (!range.length) return { total, items: [], uidValidity: String(mb.uidValidity) } } else {
        const hi = mb.exists - (page - 1) * per
        const lo = Math.max(1, hi - per + 1)
        if (hi < 1) return { total, items: [], uidValidity: String(mb.uidValidity) }
        range = `${lo}:${hi}`
      }
      const msgs = await client.fetchAll(range, { uid: true, envelope: true, flags: true, size: true, bodyStructure: true, internalDate: true }, byUid ? { uid: true } : {})
      const items = msgs.map(m => ({
        uid: m.uid,
        from: addr(m.envelope && m.envelope.from),
        to: addr(m.envelope && m.envelope.to),
        subject: (m.envelope && m.envelope.subject) || '',
        date: ((m.envelope && m.envelope.date) || m.internalDate || '') && new Date((m.envelope && m.envelope.date) || m.internalDate).toISOString(),
        seen: m.flags.has('\\Seen'), flagged: m.flags.has('\\Flagged'), answered: m.flags.has('\\Answered'),
        danger: m.flags.has('$Phishing'), size: m.size || 0, att: hasAttachment(m.bodyStructure),
        msgid: (m.envelope && m.envelope.messageId) || ''
      })).sort((a, b) => b.uid - a.uid)
      return { total, items, uidValidity: String(mb.uidValidity) }
    } finally { lock.release() }
  })
}

// ---------- Lesen ----------
const cache = new Map() // kurzer Zwischenspeicher für Inhalt/Anhänge derselben Mail
function cacheGet (k) { const e = cache.get(k); if (e && Date.now() - e.at < 5 * 60 * 1000) return e.v; cache.delete(k); return null }
function cacheSet (k, v) { cache.set(k, { at: Date.now(), v }); if (cache.size > 30) cache.delete(cache.keys().next().value) }

export async function readMessage (acc, folder, uid, { markSeen = true } = {}) {
  const key = `${(currentUser() || {}).id || 0}:${acc.id}:${folder}:${uid}`
  let msg = cacheGet(key)
  if (!msg) {
    msg = await withMail(acc, async (client) => {
      const lock = await client.getMailboxLock(folder)
      try {
        const meta = await client.fetchOne(String(uid), { uid: true, size: true, flags: true }, { uid: true })
        if (!meta) return null
        if (meta.size > MAX_SOURCE) throw new Error(`Die Mail ist zu groß zum Anzeigen (${Math.round(meta.size / 1e6)} MB).`)
        const full = await client.fetchOne(String(uid), { source: true, flags: true }, { uid: true })
        const parsed = await simpleParser(full.source, { skipImageLinks: true })
        return { parsed, flags: [...(full.flags || [])], size: meta.size, source: full.source }
      } finally { lock.release() }
    })
    if (!msg) return null
    cacheSet(key, msg)
  }
  if (markSeen && !msg.flags.includes('\\Seen')) {
    await setFlags(acc, folder, [uid], '\\Seen', true).catch(() => {})
    msg.flags.push('\\Seen')
  }
  return msg
}
export const forgetCached = (acc, folder, uid) => cache.delete(`${(currentUser() || {}).id || 0}:${acc.id}:${folder}:${uid}`)

/** Anhänge mit Sicherheitsbewertung (gefährliche werden gesperrt) */
export function attachmentsOf (parsed) {
  return (parsed.attachments || []).map((a, i) => {
    const r = scanAttachment({ filename: a.filename || '', contentType: a.contentType || '', content: a.content })
    return { i, filename: a.filename || `anhang-${i + 1}`, contentType: a.contentType || 'application/octet-stream', size: a.size || (a.content ? a.content.length : 0), cid: a.cid || '', related: !!a.related, danger: r.danger || '', warn: r.warn || '', content: a.content }
  })
}

/** Sicherheitsbewertung für die Anzeige (gleiche Prüfung wie beim Sortieren) */
export function assessForView (parsed, from) {
  const cfg = getConfig()
  const m = { from_addr: from.address, from_name: from.name, domain: from.address.split('@')[1] || '', subject: parsed.subject || '' }
  const trusted = isTrusted(m)
  const res = phishCheck({ ...m, text: parsed.text || '', html: String(parsed.html || ''), headers: parsed.headers, attachments: (parsed.attachments || []).map(a => ({ filename: a.filename || '', contentType: a.contentType || '', content: a.content })) },
    { brands: brandList(cfg.security.brands), trusted, known: isKnown(m) })
  const level = res.dangerous || res.score >= Number(cfg.security.phishThreshold || 60) ? 'bad' : res.score >= Number(cfg.security.warnThreshold || 30) ? 'warn' : ''
  return { level, score: res.score, reasons: res.reasons.map(r => r.t), trusted }
}

// ---------- HTML sicher machen ----------
const TAGS = sanitizeHtml.defaults.allowedTags.concat(['img', 'style', 'font', 'center', 'span', 'del', 's', 'u', 'small', 'big', 'tt', 'colgroup', 'col', 'thead', 'tfoot', 'h1', 'h2'])
/**
 * Mail-HTML bereinigen: keine Skripte, Formulare, Frames, Objekte; Links öffnen im neuen Fenster;
 * eingebettete Bilder (cid:) werden als data: eingesetzt; externe Bilder nur, wenn erlaubt (sonst über CSP blockiert).
 */
export function cleanMailHtml (html, attachments, { remote = false } = {}) {
  const cids = new Map()
  let budget = 8 * 1024 * 1024
  for (const a of attachments) {
    if (!a.cid || !/^image\/(png|jpe?g|gif|webp|bmp)$/i.test(a.contentType) || !a.content || a.content.length > budget) continue
    budget -= a.content.length
    cids.set(a.cid.replace(/^<|>$/g, '').toLowerCase(), `data:${a.contentType.toLowerCase()};base64,${a.content.toString('base64')}`)
  }
  let blocked = 0
  const out = sanitizeHtml(String(html || ''), {
    allowedTags: TAGS,
    allowVulnerableTags: true, // <style> erlaubt – Skripte gibt es nicht, externe Ladevorgänge sperrt die CSP des Rahmens
    allowedAttributes: { '*': ['style', 'class', 'align', 'valign', 'width', 'height', 'bgcolor', 'color', 'border', 'cellpadding', 'cellspacing', 'dir', 'lang', 'title', 'colspan', 'rowspan', 'face', 'size'], a: ['href', 'name', 'target', 'rel', 'title'], img: ['src', 'alt', 'width', 'height', 'style', 'title'] },
    allowedSchemes: ['http', 'https', 'mailto', 'tel'],
    allowedSchemesByTag: { img: ['http', 'https', 'data', 'cid'] },
    allowProtocolRelative: false,
    transformTags: {
      a: (tag, attribs) => ({ tagName: 'a', attribs: { ...attribs, target: '_blank', rel: 'noopener noreferrer', title: attribs.href ? `Ziel: ${attribs.href}` : '' } }),
      img: (tag, attribs) => {
        const src = String(attribs.src || '')
        if (/^cid:/i.test(src)) return { tagName: 'img', attribs: { ...attribs, src: cids.get(src.slice(4).replace(/^<|>$/g, '').toLowerCase()) || '' } }
        if (/^https?:/i.test(src)) { blocked++; if (!remote) return { tagName: 'img', attribs: { ...attribs, src: '', alt: attribs.alt || '' } } }
        return { tagName: 'img', attribs }
      }
    }
  })
  // Hintergrundbilder aus CSS (style-Attribute, <style>) ebenfalls nur, wenn erlaubt
  const safe = remote ? out : out.replace(/url\(\s*(['"]?)\s*(https?:|\/\/)[^)]*\)/gi, 'none').replace(/@import[^;]+;/gi, '')
  return { html: safe, remoteImages: blocked }
}
export function textToHtml (text) {
  const esc = (s) => String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]))
  return '<pre style="white-space:pre-wrap;font:14px/1.5 system-ui,sans-serif;margin:0">' + esc(text || '').replace(/https?:\/\/[^\s<]+/g, u => `<a href="${u}" target="_blank" rel="noopener noreferrer" title="Ziel: ${u}">${u}</a>`) + '</pre>'
}

export const imagesAllowed = (sender) => !!(sender && db.prepare('SELECT 1 FROM image_ok WHERE sender = ?').get(String(sender).toLowerCase()))
export const allowImages = (sender) => db.prepare('INSERT INTO image_ok (sender, created_at) VALUES (?, ?) ON CONFLICT(sender) DO NOTHING').run(String(sender).toLowerCase(), now())

// ---------- Aktionen ----------
export async function setFlags (acc, folder, uids, flag, on) {
  return withMail(acc, async (client) => {
    const lock = await client.getMailboxLock(folder)
    try {
      const list = uids.map(String).join(',')
      if (on) await client.messageFlagsAdd(list, Array.isArray(flag) ? flag : [flag], { uid: true })
      else await client.messageFlagsRemove(list, Array.isArray(flag) ? flag : [flag], { uid: true })
    } finally { lock.release() }
  })
}
export async function moveMessages (acc, folder, uids, dest) {
  if (folder === dest) return 0
  return withMail(acc, async (client) => {
    const lock = await client.getMailboxLock(folder)
    try { await client.messageMove(uids.map(String).join(','), dest, { uid: true }); return uids.length } finally { lock.release() }
  })
}
/** Löschen = in den Papierkorb; liegt die Mail schon im Papierkorb, endgültig */
export async function deleteMessages (acc, folder, uids) {
  // Kein Papierkorb vorhanden (selten): einen anlegen statt sofort endgültig zu löschen
  const trash = await withMail(acc, async (client) => (await findTrash(client)) || ensurePath(client, ['Papierkorb']))
  if (trash && trash !== folder) return { moved: await moveMessages(acc, folder, uids, trash), trash }
  await withMail(acc, async (client) => {
    const lock = await client.getMailboxLock(folder)
    try { await client.messageDelete(uids.map(String).join(','), { uid: true }) } finally { lock.release() }
  })
  return { deleted: uids.length }
}
export async function appendTo (acc, folder, raw, flags = []) {
  return withMail(acc, (client) => client.append(folder, raw, flags))
}
