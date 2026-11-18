// Mails schreiben und senden: HTML bereinigen, Nur-Text-Fassung, eingebettete Bilder (data: → cid), Gesendet-Ordner, Entwürfe.
import nodemailer from 'nodemailer'
import MailComposer from 'nodemailer/lib/mail-composer/index.js'
import sanitizeHtml from 'sanitize-html'
import { smtpOf } from './accounts.js'
import { withMail, listFolders } from './webmail.js'
import { ensurePath } from './imap.js'
import { db, now, log } from './db.js'
import { VERSION } from './html.js'

export const MAX_TOTAL = 25 * 1024 * 1024 // Anhänge + Bilder zusammen
const EMAIL = /^[^\s@<>()",;:\\[\]]{1,64}@[a-z0-9.-]{1,253}\.[a-z]{2,63}$/i

/** „Name <a@b.de>, c@d.de“ → [{ name, address }] (streng geprüft, max. 50) */
export function parseRecipients (s) {
  const out = []
  for (const part of String(s || '').split(/[,;\n]+/).map(x => x.trim()).filter(Boolean)) {
    const m = part.match(/^(?:"?([^"<>]*?)"?\s*)?<([^<>\s]+)>$/) || part.match(/^()([^<>\s]+)$/)
    if (!m || !EMAIL.test(m[2])) throw new Error(`Ungültige Adresse: ${part.slice(0, 80)}`)
    out.push({ name: String(m[1] || '').replace(/[\r\n"]/g, '').trim().slice(0, 80), address: m[2].toLowerCase() })
  }
  if (out.length > 50) throw new Error('Höchstens 50 Empfänger.')
  return out
}

// Ausgehendes HTML: nur Formatierung, Links, Bilder (data:, https), Tabellen – nichts Ausführbares
export function cleanOutgoing (html) {
  return sanitizeHtml(String(html || ''), {
    allowedTags: ['p', 'div', 'span', 'br', 'b', 'strong', 'i', 'em', 'u', 's', 'strike', 'del', 'sub', 'sup', 'small', 'font', 'a', 'ul', 'ol', 'li', 'blockquote',
      'h1', 'h2', 'h3', 'h4', 'hr', 'img', 'table', 'thead', 'tbody', 'tfoot', 'tr', 'td', 'th', 'pre', 'code', 'center'],
    allowedAttributes: { '*': ['style', 'align', 'dir', 'color', 'size', 'face', 'width', 'height', 'bgcolor', 'border', 'cellpadding', 'cellspacing', 'colspan', 'rowspan', 'valign', 'data-signatur', 'type'], a: ['href', 'title', 'target'], img: ['src', 'alt', 'width', 'height', 'style'] },
    allowedSchemes: ['http', 'https', 'mailto', 'tel'],
    allowedSchemesByTag: { img: ['data', 'https', 'cid'] },
    allowedStyles: { '*': { color: [/^[#a-z0-9(),.\s%]+$/i], 'background-color': [/^[#a-z0-9(),.\s%]+$/i], 'font-size': [/^[\d.]+(px|pt|em|rem|%)$/i], 'font-weight': [/^(bold|normal|\d{3})$/i], 'font-style': [/^(italic|normal)$/i], 'text-decoration': [/^[a-z\s-]+$/i], 'text-align': [/^(left|right|center|justify)$/i], 'font-family': [/^[a-z0-9 ,'"-]+$/i], margin: [/^[\d.\spxem%-]+$/i], padding: [/^[\d.\spxem%-]+$/i], 'border-left': [/^[\w\s#.()-]+$/i], width: [/^[\d.]+(px|%)$/i], height: [/^[\d.]+(px|%)$/i], 'max-width': [/^[\d.]+(px|%)$/i] } },
    transformTags: { a: (t, a) => ({ tagName: 'a', attribs: { ...a, target: '_blank' } }) }
  })
}

export function htmlToText (html) {
  return String(html || '')
    .replace(/<(style|script)[\s\S]*?<\/\1>/gi, '')
    .replace(/<(ul|ol|table|blockquote)[^>]*>/gi, '\n').replace(/<br\s*\/?>/gi, '\n').replace(/<\/(p|div|h\d|li|tr|blockquote)>/gi, '\n').replace(/<li[^>]*>/gi, '• ')
    .replace(/<a [^>]*href="([^"]+)"[^>]*>([\s\S]*?)<\/a>/gi, (m, href, txt) => { const t = txt.replace(/<[^>]+>/g, ''); return t && t !== href && !href.startsWith('mailto:') ? `${t} (${href})` : t || href })
    .replace(/<img[^>]*>/gi, '').replace(/<[^>]+>/g, '')
    .replace(/&nbsp;/g, ' ').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&amp;/g, '&')
    .replace(/[ \t]+\n/g, '\n').replace(/\n{3,}/g, '\n\n').trim()
}

const isLocal = (h) => /^(localhost|127\.\d+\.\d+\.\d+|::1)$/i.test(h)
export function transportFor (acc) {
  const c = smtpOf(acc)
  if (!c.host) throw new Error('Kein Postausgangsserver eingetragen (Einstellungen → Postfächer → Postausgang).')
  if (!c.pass) throw new Error('Passwort für den Postausgang fehlt (Einstellungen → Postfächer).')
  return nodemailer.createTransport({
    host: c.host, port: c.port, secure: c.secure, requireTLS: !c.secure && !isLocal(c.host),
    auth: { user: c.user, pass: c.pass }, disableFileAccess: true, disableUrlAccess: true,
    connectionTimeout: 20000, greetingTimeout: 15000, socketTimeout: 60000,
    tls: acc.allow_self_signed ? { rejectUnauthorized: false } : undefined
  })
}
export async function testSmtp (acc) { await transportFor(acc).verify() }

/** Rohe Mail bauen (RFC 5322). Liefert { raw, envelope, messageId } */
export async function buildMessage (acc, m) {
  const c = smtpOf(acc)
  const from = { name: c.fromName || '', address: String(acc.user || '').toLowerCase() }
  if (!EMAIL.test(from.address)) throw new Error('Die Absenderadresse des Postfachs ist keine gültige Mail-Adresse (Benutzername prüfen).')
  let html = m.plain ? null : cleanOutgoing(m.html)
  // Eingefügte Bilder (data:) als eingebettete Anhänge (cid:) mitschicken – data:-Bilder zeigen viele Mailprogramme nicht an
  const inline = []
  if (html) {
    const seenImg = new Map()
    html = html.replace(/src="data:(image\/(?:png|jpe?g|gif|webp));base64,([A-Za-z0-9+/=\s]+)"/gi, (all, type, data) => {
      const key = data.length + ':' + data.slice(0, 64) + data.slice(-64)
      if (!seenImg.has(key)) {
        const cid = `bild${inline.length + 1}.${Date.now().toString(36)}@mail-sortierer`
        inline.push({ cid, contentType: type.toLowerCase(), content: Buffer.from(data.replace(/\s+/g, ''), 'base64'), filename: `bild${inline.length + 1}.${type.split('/')[1].replace('jpeg', 'jpg')}`, contentDisposition: 'inline' })
        seenImg.set(key, cid)
      }
      return `src="cid:${seenImg.get(key)}"`
    })
  }
  const text = m.plain ? String(m.text || '') : htmlToText(html)
  const size = (html || text).length + [...(m.attachments || []), ...inline].reduce((s, a) => s + a.content.length, 0)
  if (size > MAX_TOTAL) throw new Error('Die Mail ist zu groß (höchstens 25 MB mit Anhängen und Bildern).')
  const domain = from.address.split('@')[1]
  const messageId = `<${Date.now().toString(36)}.${Math.random().toString(36).slice(2, 10)}@${domain}>`
  const opts = {
    from, to: m.to, cc: m.cc && m.cc.length ? m.cc : undefined, bcc: m.bcc && m.bcc.length ? m.bcc : undefined,
    subject: String(m.subject || '').replace(/[\r\n]+/g, ' ').slice(0, 300), text, html: html || undefined,
    attachments: [...(m.attachments || []).map(a => ({ filename: a.filename, content: a.content, contentType: a.contentType })), ...inline],
    messageId, date: new Date(), inReplyTo: m.inReplyTo || undefined, references: m.references || undefined,
    disableFileAccess: true, disableUrlAccess: true,
    headers: { 'X-Mailer': `Mail-Sortierer ${VERSION}` }
  }
  const mc = new MailComposer(opts)
  const node = mc.compile()
  node.keepBcc = !!m.draft // Bcc nur im Entwurf behalten, nie beim Versand
  const raw = await node.build()
  const envelope = { from: from.address, to: [...m.to, ...(m.cc || []), ...(m.bcc || [])].map(x => x.address) }
  return { raw, envelope, messageId }
}

async function folderBy (acc, use, names, create) {
  const list = await listFolders(acc)
  const f = list.find(x => x.special === use) || list.find(x => names.includes(x.name.toLowerCase()) || names.includes(x.path.toLowerCase()))
  if (f) return f.path
  return withMail(acc, (client) => ensurePath(client, [create]))
}
export const sentFolder = (acc) => folderBy(acc, '\\Sent', ['sent', 'gesendet', 'gesendete elemente', 'sent items', 'sent messages', 'inbox.sent'], 'Gesendet')
export const draftsFolder = (acc) => folderBy(acc, '\\Drafts', ['drafts', 'entwürfe', 'entwurf', 'inbox.drafts'], 'Entwürfe')

/** Senden + Kopie in „Gesendet“ (+ Original als beantwortet markieren) */
export async function sendMessage (acc, m) {
  if (!m.to.length && !(m.cc || []).length && !(m.bcc || []).length) throw new Error('Bitte mindestens einen Empfänger angeben.')
  const { raw, envelope, messageId } = await buildMessage(acc, m)
  await transportFor(acc).sendMail({ envelope, raw })
  let sentCopy = ''
  try {
    const sent = await sentFolder(acc)
    await withMail(acc, (client) => client.append(sent, raw, ['\\Seen']))
    sentCopy = sent
  } catch (e) { log('warn', `Gesendet, aber Kopie in „Gesendet“ fehlgeschlagen: ${e.message}`) }
  if (m.replyTo) {
    await withMail(acc, async (client) => {
      const lock = await client.getMailboxLock(m.replyTo.folder)
      try { await client.messageFlagsAdd(String(m.replyTo.uid), [m.replyTo.forward ? '$Forwarded' : '\\Answered'], { uid: true }) } catch { /* egal */ } finally { lock.release() }
    }).catch(() => {})
  }
  if (m.draft && m.draft.uid) await deleteDraft(acc, m.draft).catch(() => {})
  log('info', `Mail gesendet an ${envelope.to.length} Empfänger: „${String(m.subject || '').slice(0, 80)}“`)
  return { messageId, sentCopy }
}

export async function saveDraft (acc, m) {
  const { raw } = await buildMessage(acc, { ...m, draft: { keep: true } })
  const folder = await draftsFolder(acc)
  const r = await withMail(acc, (client) => client.append(folder, raw, ['\\Draft', '\\Seen']))
  if (m.draft && m.draft.uid) await deleteDraft(acc, m.draft).catch(() => {})
  return { folder, uid: r && r.uid }
}
async function deleteDraft (acc, d) {
  await withMail(acc, async (client) => {
    const lock = await client.getMailboxLock(d.folder)
    try { await client.messageDelete(String(d.uid), { uid: true }) } finally { lock.release() }
  })
}

// ---------- Signaturen ----------
export const listSignatures = () => db.prepare('SELECT * FROM signatures ORDER BY name').all()
export const getSignature = (id) => db.prepare('SELECT * FROM signatures WHERE id = ?').get(Number(id))
export function saveSignature (id, name, html) {
  const n = String(name || '').trim().slice(0, 60)
  if (!n) throw new Error('Bitte einen Namen angeben.')
  const h = cleanOutgoing(html)
  if (h.length > 3 * 1024 * 1024) throw new Error('Signatur zu groß (Logo bitte verkleinern, höchstens ca. 2 MB).')
  if (id && getSignature(id)) { db.prepare('UPDATE signatures SET name = ?, html = ?, updated_at = ? WHERE id = ?').run(n, h, now(), Number(id)); return Number(id) }
  return Number(db.prepare('INSERT INTO signatures (name, html, created_at, updated_at) VALUES (?, ?, ?, ?)').run(n, h, now(), now()).lastInsertRowid)
}
export function deleteSignature (id) {
  db.prepare('DELETE FROM signatures WHERE id = ?').run(Number(id))
  db.prepare('UPDATE accounts SET sig_new = NULL WHERE sig_new = ?').run(Number(id))
  db.prepare('UPDATE accounts SET sig_reply = NULL WHERE sig_reply = ?').run(Number(id))
}
