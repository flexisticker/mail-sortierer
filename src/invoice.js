// Rechnungen: auslesen (E-Rechnung/PDF/KI), nach Jahr/Monat im Sammel-Postfach ablegen, Scanner-Ordner, Lexware Office.
import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import zlib from 'node:zlib'
import { simpleParser } from 'mailparser'
import { db, now, log, dataDir, kvGet, kvSet } from './db.js'
import { getConfig, companyList, PLATFORM } from './config.js'
import { execFile } from 'node:child_process'
import { pdfStreams, pdfRisk, scanAttachment } from './security.js'
import { FREEMAIL } from './learn.js'
import { licensedFull } from './license.js'
import { chatJson } from './ollama.js'
import { getAccount, accountLabel } from './accounts.js'
import { withClient, ensurePath, appendMessage, moveMessage, findByMsgId, pathString } from './imap.js'
import { getSecret } from './secrets.js'

const belegeDir = () => path.join(dataDir(), 'belege')
const MAX_SOURCE = 40 * 1024 * 1024
const MONTHS = ['Januar', 'Februar', 'März', 'April', 'Mai', 'Juni', 'Juli', 'August', 'September', 'Oktober', 'November', 'Dezember']
export const monthName = (ym) => { const m = Number(String(ym).slice(5, 7)); return m ? MONTHS[m - 1] : '' }

const byId = { get: (id) => db.prepare('SELECT * FROM invoices WHERE id = ?').get(id) }
export const getInvoice = (id) => byId.get(Number(id))

function upd (id, f) {
  const k = Object.keys(f)
  db.prepare(`UPDATE invoices SET ${k.map(x => x + ' = ?').join(', ')}, updated_at = ? WHERE id = ?`).run(...k.map(x => f[x] ?? null), now(), id)
}

// Jahr schon erledigt? (Einstellung „Zu Lexware prüfen ab Jahr“)
export const yearClosed = (ym, cfg = getConfig()) => Number(cfg.invoices.fromYear) > 0 && Number(String(ym).slice(0, 4)) < Number(cfg.invoices.fromYear)

export function collecting (cfg = getConfig()) {
  const acc = cfg.invoices.accountId ? getAccount(cfg.invoices.accountId) : null
  return acc && acc.enabled ? acc : null
}

// ---------- Auslesen ----------

const tag = (xml, name) => {
  const m = xml.match(new RegExp(`<(?:[\\w-]+:)?${name}\\b[^>]*>([^<]*)<`))
  return m ? m[1].trim() : ''
}
const block = (xml, name) => {
  const m = xml.match(new RegExp(`<(?:[\\w-]+:)?${name}\\b[^>]*>([\\s\\S]*?)</(?:[\\w-]+:)?${name}>`))
  return m ? m[1] : ''
}
const decodeXml = (s) => String(s || '').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&apos;/g, "'")

function itemNames (xml, el) {
  const names = []
  for (const m of xml.matchAll(new RegExp(`<(?:[\\w-]+:)?${el}\\b[^>]*>([\\s\\S]*?)</(?:[\\w-]+:)?${el}>`, 'g'))) {
    const n = decodeXml(tag(m[1], 'Name')).trim()
    if (n && !names.includes(n)) names.push(n)
    if (names.length >= 3) break
  }
  return names.join(', ').slice(0, 120)
}

// E-Rechnung (ZUGFeRD/Factur-X/XRechnung CII oder UBL) – exakte Angaben
export function parseEInvoice (xml) {
  xml = String(xml || '')
  if (/CrossIndustryInvoice/.test(xml)) {
    const d = tag(block(xml, 'ExchangedDocument'), 'DateTimeString') || tag(xml, 'DateTimeString')
    return {
      kind: /xrechnung/i.test(tag(xml, 'ID') + block(xml, 'GuidelineSpecifiedDocumentContextParameter')) ? 'xrechnung' : 'zugferd',
      number: decodeXml(tag(block(xml, 'ExchangedDocument'), 'ID')),
      date: /^\d{8}$/.test(d) ? `${d.slice(0, 4)}-${d.slice(4, 6)}-${d.slice(6, 8)}` : '',
      supplier: decodeXml(tag(block(xml, 'SellerTradeParty'), 'Name')),
      amount: Number(tag(xml, 'GrandTotalAmount')) || null,
      currency: tag(xml, 'InvoiceCurrencyCode') || 'EUR',
      content: itemNames(xml, 'SpecifiedTradeProduct')
    }
  }
  if (/<(?:[\w-]+:)?Invoice\b[\s\S]*urn:oasis:names:specification:ubl/.test(xml) || /<(?:[\w-]+:)?CreditNote\b/.test(xml)) {
    const sup = block(xml, 'AccountingSupplierParty')
    const top = xml.replace(/<(?:[\w-]+:)?(AccountingSupplierParty|AccountingCustomerParty|InvoiceLine|CreditNoteLine)\b[\s\S]*?<\/(?:[\w-]+:)?\1>/g, '')
    const amt = xml.match(/<(?:[\w-]+:)?PayableAmount\b[^>]*currencyID="([A-Z]{3})"[^>]*>([^<]+)</)
    return {
      kind: 'xrechnung',
      number: decodeXml(tag(top, 'ID')),
      date: tag(top, 'IssueDate'),
      supplier: decodeXml(tag(sup, 'RegistrationName') || tag(sup, 'Name')),
      amount: amt ? Number(amt[2]) : null,
      currency: amt ? amt[1] : 'EUR',
      content: itemNames(xml, 'Item')
    }
  }
  return null
}

// In ZUGFeRD-PDFs steckt die XML als eingebettete Datei (meist FlateDecode-Stream)
export function embeddedXml (pdf) {
  for (const { data } of pdfStreams(pdf)) {
    if (data.length > 5 * 1024 * 1024) continue
    const t = data.toString('utf8')
    if (/CrossIndustryInvoice|urn:oasis:names:specification:ubl:schema:xsd:Invoice/.test(t) && t.includes('<')) return t.slice(t.indexOf('<'))
  }
  return ''
}

export async function pdfText (buf) {
  try {
    const { getDocumentProxy, extractText } = await import('unpdf')
    const work = (async () => {
      const doc = await getDocumentProxy(new Uint8Array(buf), { isEvalSupported: false, disableFontFace: true, useSystemFonts: false, enableXfa: false, stopAtErrors: false })
      const { text } = await extractText(doc, { mergePages: true })
      return text
    })()
    const text = await Promise.race([work, new Promise(resolve => setTimeout(() => resolve(''), 20000))])
    return String(text || '').replace(/\s+/g, ' ').trim().slice(0, 5000)
  } catch { return '' }
}

const INV_SCHEMA = {
  type: 'object',
  properties: {
    ist_rechnung: { type: 'boolean' },
    belegart: { type: 'string', enum: ['rechnung', 'gutschrift', 'auftragsbestaetigung', 'sonstiges'] },
    lieferant: { type: 'string' },
    nummer: { type: 'string' },
    datum: { type: 'string' },
    betrag: { type: ['number', 'null'] },
    waehrung: { type: 'string' },
    inhalt: { type: 'string' },
    zuordnung: { type: 'string', enum: ['firma', 'privat', 'unklar'] },
    firma: { type: 'string' },
    grund: { type: 'string' }
  },
  required: ['ist_rechnung', 'belegart', 'lieferant', 'nummer', 'datum', 'betrag', 'waehrung', 'inhalt', 'zuordnung', 'firma', 'grund']
}

async function kiExtract (cfg, { from, subject, text, fileName, examples }) {
  const companies = companyList(cfg)
  const owner = String(cfg.invoices.ownerName || '').trim()
  const biz = cfg.business || {}
  const shots = []
  for (const x of examples || []) {
    shots.push({ role: 'user', content: `Von: ${x.from_addr || '-'}\nInhalt:\n${String(x.snippet || '').slice(0, 800)}` })
    shots.push({ role: 'assistant', content: JSON.stringify({
      ist_rechnung: x.decision !== 'noinvoice' && x.decision !== 'order',
      belegart: x.decision === 'order' ? 'auftragsbestaetigung' : x.decision === 'noinvoice' ? 'sonstiges' : 'rechnung', lieferant: x.supplier || '', nummer: x.number || '', datum: x.inv_date || '', betrag: x.amount ?? null, waehrung: 'EUR',
      inhalt: x.content || '', zuordnung: x.decision === 'private' ? 'privat' : x.brand || x.decision === 'business' ? 'firma' : 'unklar', firma: x.brand || '',
      grund: 'So wurde es geprüft.' }) })
  }
  const r = await chatJson(cfg, [
    { role: 'system', content: [
      `Du liest Rechnungen ${biz.name || biz.description ? `für ${[biz.name, biz.description].filter(Boolean).join(' – ')}` : 'für einen kleinen Betrieb'} aus.`,
      'ist_rechnung: true nur für eine echte Rechnung oder Gutschrift (Beleg für die Buchhaltung) – nicht für Zahlungsbestätigung, Mahnung ohne Rechnung, Kontoauszug, Bestellbestätigung, Angebot oder Werbung.',
      'belegart: „rechnung“, „gutschrift“, „auftragsbestaetigung“ (Auftrags-/Bestellbestätigung, Order Confirmation – noch keine Rechnung) oder „sonstiges“.',
      'lieferant: Firma, die die Rechnung stellt (kurz, ohne Rechtsform-Zusätze wenn eindeutig). nummer: Rechnungsnummer genau wie gedruckt.',
      'inhalt: worum es geht, kurz in höchstens 8 Wörtern (z. B. „PLA-Filament 10 kg“, „Telefon/Internet Oktober“, „Webhosting 2027“).',
      'datum: Rechnungsdatum als JJJJ-MM-TT (nicht Liefer- oder Fälligkeitsdatum), leer wenn unbekannt. betrag: Gesamtbetrag brutto als Zahl mit Punkt, null wenn unbekannt. waehrung: z. B. EUR.',
      owner || companies.length ? `Rechnungsempfänger ist ${owner || 'der Inhaber'}.${companies.length ? ` Seine Firmen/Marken: ${companies.join(', ')}.` : ''}` : 'Rechnungsempfänger ist der Inhaber des Betriebs.',
      `zuordnung: „firma“, wenn eine dieser Firmen in der Anschrift steht oder der Inhalt eindeutig gewerblich ist (Material, Maschinen, Druck, Software, Versand, Werbung, Webhosting); dann firma = Name der Firma aus der Liste, sonst leer.`,
      `„privat“, wenn nur ${owner ? `„${owner}“` : 'ein Personenname'} ohne Firma dasteht und der Inhalt eindeutig privat ist (Streaming, Kleidung, private Versicherung, Lebensmittel, Urlaub). „unklar“, wenn du es nicht sicher sagen kannst – lieber unklar als falsch.`,
      'Beachte die Beispiele: so wurden ähnliche Belege selbst geprüft und korrigiert – Schreibweise des Lieferanten und Zuordnung übernehmen.',
      'grund: höchstens 10 Wörter. Antworte nur mit JSON.'
    ].join('\n') },
    ...shots,
    { role: 'user', content: `Von: ${from || '-'}\nBetreff: ${subject || '-'}\nDatei: ${fileName || '-'}\nInhalt:\n${String(text || '(kein Text lesbar)').slice(0, 4000)}` }
  ], INV_SCHEMA)
  const date = /^\d{4}-\d{2}-\d{2}$/.test(String(r.datum || '')) ? r.datum : ''
  return {
    isInvoice: r.ist_rechnung !== false,
    order: r.belegart === 'auftragsbestaetigung',
    supplier: String(r.lieferant || '').slice(0, 120),
    number: String(r.nummer || '').slice(0, 80),
    date,
    amount: typeof r.betrag === 'number' && isFinite(r.betrag) ? Math.round(r.betrag * 100) / 100 : null,
    currency: /^[A-Z]{3}$/.test(String(r.waehrung || '')) ? r.waehrung : 'EUR',
    assignment: ['firma', 'privat', 'unklar'].includes(r.zuordnung) ? r.zuordnung : 'unklar',
    content: String(r.inhalt || '').replace(/\s+/g, ' ').trim().slice(0, 120),
    company: companies.find(c => c.toLowerCase() === String(r.firma || '').trim().toLowerCase()) || '',
    reason: String(r.grund || '').slice(0, 150)
  }
}

// Steht eine der eigenen Firmen (z. B. „Max Muster – Musterdruck“) im Beleg? → geschäftlich + Marke
const flat = (s) => String(s || '').toLowerCase().replace(/[^a-z0-9äöüß]+/g, ' ')
export function detectCompany (text, cfg) {
  // Mail- und Web-Adressen zählen nicht (rechnung@eigene-firma.de stünde sonst in jeder Mail)
  const clean = String(text || '').replace(/[^\s<>()"',;]+@[^\s<>()"',;]+/g, ' ')
    .replace(/(?:https?:\/\/|www\.)\S+/gi, ' ')
    .replace(/\b[\w-]+\.(?:de|com|net|org|eu|shop|io|info|at|ch|biz)\b/gi, ' ')
  const t = ' ' + flat(clean) + ' '
  const owner = flat(cfg.invoices.ownerName || '').trim()
  let best = null
  for (const c of companyList(cfg)) {
    const k = ' ' + flat(c).trim() + ' '
    if (k.trim().length < 3) continue
    let i = t.indexOf(k)
    while (i >= 0) {
      // Abstand zum Namen des Inhabers – die Firma direkt neben dem Namen gewinnt
      const near = owner ? Math.min(...[t.lastIndexOf(owner, i), t.indexOf(owner, i)].filter(x => x >= 0).map(x => Math.abs(x - i)), 9999) : 9999
      if (!best || near < best.near) best = { company: c, near }
      i = t.indexOf(k, i + 1)
    }
  }
  return best ? best.company : ''
}

const norm = (s) => String(s || '').toLowerCase().replace(/[^a-z0-9äöüß]/g, '')
export function dedupeKey ({ number, amount, supplier }) {
  const n = norm(number)
  if (!n || n.length < 3) return null
  if (amount != null) return `${n}|${Number(amount).toFixed(2)}`
  const s = norm(supplier).slice(0, 12)
  return s ? `${n}|${s}` : null
}
export const supplierKey = (supplier, from) => norm(supplier).slice(0, 30) || String(from || '').toLowerCase()

// Gemerkte Entscheidungen je Lieferant → Vorschlag geschäftlich/privat
function learnedSuggestion (key) {
  const d = kvGet('invoiceDecisions', {})[key]
  if (!d) return null
  if ((d.private || 0) > (d.business || 0)) return 'private'
  if ((d.business || 0) > 0) return 'business'
  return null
}
function learnDecision (inv, kind) {
  const key = supplierKey(inv.supplier, inv.from_addr)
  if (!key) return
  const all = kvGet('invoiceDecisions', {})
  const d = all[key] || {}
  d[kind] = (d[kind] || 0) + 1
  all[key] = d
  kvSet('invoiceDecisions', all)
}

const domainOf = (addr) => String(addr || '').toLowerCase().split('@')[1] || ''
const realSender = (addr) => addr && addr.includes('@') ? addr.toLowerCase() : ''

// Jede Prüfung wird gemerkt: als Beispiel für die KI und als feste Zuordnung Absender → Lieferantenname/Firma
export function invLearn (inv, decision) {
  const from = realSender(inv.from_addr)
  const domain = domainOf(from)
  db.prepare(`INSERT INTO inv_examples (invoice_id, from_addr, domain, supplier, brand, number, inv_date, amount, content, decision, snippet, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(inv.id ?? null, from || null, domain || null, inv.supplier || '', inv.brand || '', inv.number || '', inv.inv_date || '',
    inv.amount ?? null, inv.content || '', decision, String(inv.text_snippet || inv.subject || '').slice(0, 800), now())
  db.prepare('DELETE FROM inv_examples WHERE id NOT IN (SELECT id FROM inv_examples ORDER BY id DESC LIMIT 2000)').run()
  if (decision === 'business' || decision === 'private' || decision === 'noinvoice') learnDecision(inv, decision)
  // Absender/Domain → so heißt der Lieferant, diese Firma (nur bei echten Absendern, nicht bei Scans)
  if (from && decision !== 'noinvoice') {
    const al = kvGet('supplierAlias', {})
    const val = { supplier: inv.supplier || '', brand: decision === 'private' ? '' : (inv.brand || ''), private: decision === 'private', at: now() }
    al['m:' + from] = { ...(al['m:' + from] || {}), ...val }
    if (domain && !FREEMAIL.has(domain)) al['d:' + domain] = { ...(al['d:' + domain] || {}), ...val }
    kvSet('supplierAlias', al)
  }
}
export function aliasFor (from) {
  const al = kvGet('supplierAlias', {})
  const f = realSender(from)
  return al['m:' + f] || (domainOf(f) && !FREEMAIL.has(domainOf(f)) ? al['d:' + domainOf(f)] : null) || null
}
function invExamplesFor (from) {
  const f = realSender(from)
  if (!f) return []
  return db.prepare("SELECT * FROM inv_examples WHERE (from_addr = ? OR domain = ?) AND snippet <> '' ORDER BY id DESC LIMIT 3").all(f, FREEMAIL.has(domainOf(f)) ? '-' : domainOf(f))
}
export function forgetInvoiceLearning (id) {
  db.prepare('DELETE FROM inv_examples WHERE id = ?').run(Number(id))
}

const safeName = (s) => String(s || 'rechnung').normalize('NFKC').replace(/[^\w.äöüÄÖÜß() -]+/g, '_').replace(/\s+/g, ' ').trim().slice(0, 100) || 'rechnung'

function storeFile (buf, name, ym) {
  const hash = crypto.createHash('sha256').update(buf).digest('hex')
  const dir = path.join(belegeDir(), ym.slice(0, 4) || 'ohne-datum')
  fs.mkdirSync(dir, { recursive: true })
  const file = path.join(dir, `${hash.slice(0, 10)}-${safeName(name)}`)
  if (!fs.existsSync(file)) fs.writeFileSync(file, buf)
  return { file: path.relative(dataDir(), file), hash }
}

export const filePath = (rel) => {
  const p = path.resolve(dataDir(), String(rel || ''))
  return p.startsWith(belegeDir() + path.sep) ? p : null
}

const ymOf = (date, fallback) => {
  const d = /^\d{4}-\d{2}/.test(String(date || '')) ? String(date) : (fallback ? new Date(fallback).toISOString() : new Date().toISOString())
  return d.slice(0, 7)
}
// Auftrags-/Bestellbestätigung erkennen: Betreff/Dateiname bzw. Anfang des Belegs, sonst Einschätzung der KI
const ORDER_RE = /auftrags[\s-]?best(ä|ae|a)tigung|bestell[\s-]?best(ä|ae|a)tigung|best(ä|ae|a)tigung (ihrer|der|zu ihrer) (bestellung|auftrag)|order confirmation|order acknowledg|confirmation de commande/i
const INVOICE_RE = /\b(rechnung|invoice|faktura|gutschrift|rechnungsnummer|rechnungsdatum)\b/i
export function isOrderConfirmation ({ subject, fileName, text, ki }) {
  const head = `${subject || ''} ${fileName || ''}`
  if (ORDER_RE.test(head) && !INVOICE_RE.test(head)) return true
  const top = String(text || '').slice(0, 600)
  if (ORDER_RE.test(top) && !INVOICE_RE.test(top)) return true
  return !!ki && !INVOICE_RE.test(head)
}
export function orderParts (cfg, ym) {
  return [cfg.invoices.root || 'Rechnungen', cfg.invoices.orderName || 'Auftragsbestätigungen', ym.slice(0, 4)]
}

export function monthParts (cfg, ym) {
  return [cfg.invoices.root || 'Rechnungen', ym.slice(0, 4), ym]
}

function findDuplicate (hash, key) {
  if (hash) {
    const h = db.prepare("SELECT * FROM invoices WHERE file_hash = ? AND status NOT IN ('error', 'duplicate') LIMIT 1").get(hash)
    if (h) return h
  }
  if (key) return db.prepare("SELECT * FROM invoices WHERE dedupe = ? AND status NOT IN ('error', 'duplicate', 'order') LIMIT 1").get(key)
  return null
}

// Beleg-Dateien + Angaben aus einer Mail (oder einem Scan) bestimmen
export async function analyze (cfg, { source, pdf, pdfName, from, subject, mailDate, text }) {
  let toLine = ''
  const riskyAtts = []
  let pdfBuf = pdf || null
  let fileName = pdfName || ''
  let xml = ''
  let bodyText = text || ''
  if (source) {
    const parsed = await simpleParser(source, { skipImageLinks: true, skipTextToHtml: true })
    bodyText = parsed.text || String(parsed.html || '').replace(/<[^>]+>/g, ' ')
    const atts = parsed.attachments || []
    toLine = [parsed.to && parsed.to.text, parsed.cc && parsed.cc.text].filter(Boolean).join(' ')
    for (const a of atts) { const r = scanAttachment({ filename: a.filename, contentType: a.contentType, content: a.content }); if (r.danger) riskyAtts.push(r.danger) }
    const pdfs = atts.filter(a => /pdf/i.test(a.contentType) || /\.pdf$/i.test(a.filename || ''))
    pdfs.sort((a, b) => (/rechnung|invoice|faktura|beleg/i.test(b.filename || '') ? 1 : 0) - (/rechnung|invoice|faktura|beleg/i.test(a.filename || '') ? 1 : 0))
    if (pdfs[0]) { pdfBuf = pdfs[0].content; fileName = pdfs[0].filename || 'rechnung.pdf' }
    const x = atts.find(a => /xml/i.test(a.contentType) || /\.xml$/i.test(a.filename || ''))
    if (x) xml = x.content.toString('utf8')
  }
  if (!xml && pdfBuf) xml = embeddedXml(pdfBuf)
  const e = xml ? parseEInvoice(xml) : null
  const text2 = pdfBuf ? await pdfText(pdfBuf) : ''
  let k = null
  try {
    k = await kiExtract(cfg, { from, subject, text: (text2 ? `[PDF] ${text2}\n[Mail] ` : '') + String(bodyText || '').slice(0, 1500), fileName, examples: invExamplesFor(from) })
  } catch (err) {
    if (!e) throw err // ohne E-Rechnung brauchen wir die KI
  }
  const info = {
    isInvoice: e ? true : (k ? k.isInvoice : true),
    supplier: (e && e.supplier) || (k && k.supplier) || '',
    number: (e && e.number) || (k && k.number) || '',
    date: (e && e.date) || (k && k.date) || '',
    amount: e && e.amount != null ? e.amount : (k ? k.amount : null),
    currency: (e && e.currency) || (k && k.currency) || 'EUR',
    einvoice: e ? e.kind : '',
    content: (k && k.content) || (e && e.content) || '',
    assignment: k ? k.assignment : 'unklar',
    reason: k ? k.reason : 'E-Rechnung',
    pdf: pdfBuf, fileName, xml: xml && e ? xml : ''
  }
  info.order = !e && isOrderConfirmation({ subject, fileName, text: text2, ki: k && k.order })
  info.ym = ymOf(info.date, mailDate)
  info.snippet = String(text2 || bodyText || '').replace(/\s+/g, ' ').trim().slice(0, 800)
  // Firma: zuerst wörtlich im Beleg/der Mail suchen, dann Gelerntes zum Absender, sonst Einschätzung der KI
  const alias = aliasFor(from)
  info.brand = detectCompany(`${text2}\n${bodyText}\n${toLine || ''}\n${xml || ''}`, cfg)
  if (alias) {
    if (alias.supplier) info.supplier = alias.supplier
    if (!info.brand && alias.brand) { info.brand = alias.brand; info.reason = 'wie bisher bei diesem Absender' }
    if (!info.brand && alias.private) { info.assignment = 'privat'; info.reason = 'bisher immer privat' }
  }
  if (!info.brand && k && k.assignment === 'firma' && (!alias || !alias.private)) info.brand = k.company
  // Sicherheit: riskante PDF/Anhänge → Beleg gesperrt
  info.risk = []
  if (pdfBuf) info.risk.push(...pdfRisk(pdfBuf))
  for (const a of riskyAtts) info.risk.push(a)
  return info
}

function insertInvoice (f) {
  const t = now()
  const r = db.prepare(`INSERT INTO invoices (source, account_id, mail_id, msgid, from_addr, subject, supplier, number, inv_date, amount, currency, einvoice,
    file, file_name, file_hash, xml_file, dedupe, folder, uid, same_message, suggestion, hint, status, created_at, updated_at, brand, risk, content, text_snippet)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(f.source, f.account_id ?? null, f.mail_id ?? null, f.msgid ?? null, f.from_addr ?? null, f.subject ?? null, f.supplier || '', f.number || '', f.inv_date || '',
      f.amount ?? null, f.currency || 'EUR', f.einvoice || '', f.file ?? null, f.file_name ?? null, f.file_hash ?? null, f.xml_file ?? null, f.dedupe ?? null,
      f.folder ?? null, f.uid ?? null, f.same_message ? 1 : 0, f.suggestion ?? null, f.hint ?? null, f.status, t, t, f.brand || null, f.risk ? JSON.stringify(f.risk) : null, f.content || null, f.text_snippet || null)
  return byId.get(Number(r.lastInsertRowid))
}

function storeDocs (info) {
  const out = {}
  if (info.pdf) Object.assign(out, (({ file, hash }) => ({ file, file_hash: hash }))(storeFile(info.pdf, info.fileName || 'rechnung.pdf', info.ym)), { file_name: info.fileName || 'rechnung.pdf' })
  if (info.xml) {
    const x = storeFile(Buffer.from(info.xml, 'utf8'), (info.number ? 'e-rechnung-' + info.number : 'e-rechnung') + '.xml', info.ym)
    out.xml_file = x.file
    if (!out.file) { out.file = x.file; out.file_name = 'e-rechnung.xml'; out.file_hash = x.hash }
  }
  return out
}

function suggestionFor (info, from) {
  if (info.brand) return 'business'
  const learned = learnedSuggestion(supplierKey(info.supplier, from))
  if (learned) return learned
  return info.assignment === 'firma' ? 'business' : info.assignment === 'privat' ? 'private' : 'check'
}

// ---------- Mail im Posteingang eines Postfachs ist eine Rechnung ----------
// Rückgabe { folder, uid } wenn die Mail selbst (im Sammel-Postfach) in den Monatsordner verschoben wurde, sonst null.
export async function handleMailInvoice (ctx, acc, rec, client) {
  const cfg = getConfig()
  const target = collecting(cfg)
  if (!target) return null
  const m = await client.fetchOne(String(rec.uid), { size: true }, { uid: true })
  if (!m) return null
  if (m.size > MAX_SOURCE) { log('warn', `Rechnung „${rec.subject}“ ist zu groß (${Math.round(m.size / 1e6)} MB) – bitte von Hand ablegen`); return null }
  const src = (await client.fetchOne(String(rec.uid), { source: true }, { uid: true })).source
  const info = await analyze(cfg, { source: src, from: rec.from_addr, subject: rec.subject, mailDate: rec.date })
  if (!info.isInvoice && !info.pdf && !info.xml) return null // Zahlungsmeldung o. ä.: nur einsortieren
  if (info.risk.length) {
    // Gefährlicher Beleg: nicht kopieren, nicht ablegen – Mail kommt nach „Achtung Verdacht“
    insertInvoice({ source: 'mail', account_id: acc.id, mail_id: rec.id, msgid: rec.msgid, from_addr: rec.from_addr, subject: rec.subject, ...storeDocs(info), brand: info.brand,
      supplier: info.supplier, number: info.number, inv_date: info.date, content: info.content, text_snippet: info.snippet, amount: info.amount, currency: info.currency, status: 'blocked', risk: info.risk, hint: 'Beleg gesperrt: ' + info.risk.join('; ') })
    log('warn', `Rechnung „${rec.subject}“ von ${rec.from_addr} gesperrt: ${info.risk.join('; ')}`)
    return { blocked: 'Gefährlicher Rechnungsanhang: ' + info.risk.join('; ') }
  }
  const docs = storeDocs(info)
  const key = info.order ? null : dedupeKey(info)
  const dup = findDuplicate(docs.file_hash, key)
  const base = {
    source: 'mail', account_id: acc.id, mail_id: rec.id, msgid: rec.msgid, from_addr: rec.from_addr, subject: rec.subject,
    supplier: info.supplier, number: info.number, inv_date: info.date, content: info.content, text_snippet: info.snippet, amount: info.amount, currency: info.currency, einvoice: info.einvoice,
    ...docs, dedupe: key, brand: info.brand, suggestion: suggestionFor(info, rec.from_addr), hint: info.isInvoice ? info.reason : 'KI: eher keine Rechnung – bitte prüfen'
  }
  if (dup) {
    insertInvoice({ ...base, status: 'duplicate', hint: `doppelt – schon vorhanden (#${dup.id})` })
    log('info', `Rechnung ${info.number || rec.subject} ist doppelt (schon #${dup.id}) – nicht erneut abgelegt`)
    return null
  }
  const parts = info.order ? orderParts(cfg, info.ym) : monthParts(cfg, info.ym)
  const closed = yearClosed(info.ym, cfg)
  // Ohne Beleg (nur Hinweis „Rechnung im Kundenkonto“ o. ä.): ablegen, aber nichts zu prüfen – kein Fähnchen
  const nodoc = !docs.file
  const st = info.order ? 'order' : closed ? 'archived' : nodoc ? 'nodoc' : 'open'
  if (info.order) base.hint = 'Auftragsbestätigung – nichts zu prüfen'
  else if (nodoc) base.hint = 'kein Beleg in der Mail – nichts zu prüfen'
  const flags = cfg.invoices.flagOpen && st === 'open' ? ['\\Flagged'] : []
  if (target.id === acc.id) {
    // Mail liegt schon im Sammel-Postfach → direkt in den Monatsordner
    const dest = await ensurePath(client, parts)
    if (flags.length) await client.messageFlagsAdd(String(rec.uid), flags, { uid: true })
    const newUid = await moveMessage(client, rec.uid, dest)
    insertInvoice({ ...base, folder: dest, uid: newUid, same_message: 1, status: st })
    log('info', `${info.order ? 'Auftragsbestätigung' : 'Rechnung'} abgelegt: ${info.supplier || rec.from_addr} ${info.number} → ${dest}`)
    return { folder: dest, uid: newUid }
  }
  const tc = await ctx.client(target)
  const dest = await ensurePath(tc, parts)
  const uid = await appendMessage(tc, dest, src, flags)
  insertInvoice({ ...base, folder: dest, uid, same_message: 0, status: st })
  log('info', `${info.order ? 'Auftragsbestätigung' : 'Rechnung'} aus ${accountLabel(acc)} nach ${accountLabel(target)} kopiert: ${info.supplier || rec.from_addr} ${info.number} → ${dest}`)
  return null
}

// ---------- Scanner-Ordner ----------

const b64lines = (buf) => buf.toString('base64').replace(/.{76}/g, '$&\r\n')
const encWord = (s) => `=?UTF-8?B?${Buffer.from(String(s), 'utf8').toString('base64')}?=`

export function buildScanMail ({ to, subject, text, fileName, pdf, msgid, date }) {
  const b = 'scan-' + crypto.randomBytes(8).toString('hex')
  return Buffer.from([
    'From: Scanner <scanner@mail-sortierer.invalid>',
    `To: <${to}>`,
    `Subject: ${encWord(subject)}`,
    `Date: ${(date || new Date()).toUTCString().replace('GMT', '+0000')}`,
    `Message-ID: ${msgid}`,
    'MIME-Version: 1.0',
    `Content-Type: multipart/mixed; boundary="${b}"`,
    '',
    `--${b}`,
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: base64',
    '',
    b64lines(Buffer.from(text, 'utf8')),
    `--${b}`,
    `Content-Type: application/pdf; name="${encWord(fileName)}"`,
    `Content-Disposition: attachment; filename*=UTF-8''${encodeURIComponent(fileName)}`,
    'Content-Transfer-Encoding: base64',
    '',
    b64lines(pdf),
    `--${b}--`,
    ''
  ].join('\r\n'), 'utf8')
}

function moveScanFile (dir, file, sub) {
  const destDir = path.join(dir, 'erledigt', sub)
  fs.mkdirSync(destDir, { recursive: true })
  let dest = path.join(destDir, path.basename(file))
  for (let i = 2; fs.existsSync(dest); i++) dest = path.join(destDir, path.basename(file, path.extname(file)) + ` (${i})` + path.extname(file))
  fs.renameSync(file, dest)
}

// Windows-Dienst: Netzwerkfreigabe (\\\\Server\\Freigabe) mit Benutzer/Passwort verbinden – Laufwerksbuchstaben sieht der Dienst nicht
let shareConnected = ''
async function ensureShare (dir, cfg) {
  if (PLATFORM !== 'windows' || !/^\\\\[^\\]+\\[^\\]+/.test(dir) || !cfg.invoices.scanUser) return
  const share = dir.match(/^\\\\[^\\]+\\[^\\]+/)[0]
  if (shareConnected === share && fs.existsSync(dir)) return
  const pw = getSecret('scanPassword')
  await new Promise((resolve) => execFile('net', ['use', share, pw, `/user:${cfg.invoices.scanUser}`, '/persistent:no'], { windowsHide: true, timeout: 20000 }, () => resolve()))
  shareConnected = share
}

// „Ordner prüfen“ in den Einstellungen: erreichbar, lesbar, beschreibbar (für erledigt/)?
export async function checkScanDir () {
  const cfg = getConfig()
  const dir = cfg.invoices.scanDir
  if (!dir) throw new Error('Kein Ordner eingetragen.')
  if (PLATFORM === 'windows' && /^[a-z]:/i.test(dir) && !/^c:/i.test(dir) && !fs.existsSync(dir)) throw new Error(`${dir} nicht gefunden – Laufwerksbuchstaben von Netzlaufwerken sieht der Dienst nicht, bitte \\\\Server\\Freigabe verwenden.`)
  await ensureShare(dir, cfg)
  if (!fs.existsSync(dir)) throw new Error(`${dir} nicht gefunden oder kein Zugriff.`)
  const pdfs = fs.readdirSync(dir).filter(n => /\.pdf$/i.test(n)).length
  const probe = path.join(dir, '.mail-sortierer-test')
  fs.writeFileSync(probe, 'ok'); fs.unlinkSync(probe)
  return { pdfs }
}

export async function processScans (ctx, stats) {
  const cfg = getConfig()
  const target = collecting(cfg)
  if (!cfg.invoices.scanEnabled || !target) return
  if (target.mode !== 'live') return
  const dir = cfg.invoices.scanDir
  if (dir) await ensureShare(dir, cfg).catch(() => {})
  if (!dir || !fs.existsSync(dir)) { stats.scanError = `Scanner-Ordner ${dir || '(nicht eingetragen)'} nicht gefunden`; return }
  const files = fs.readdirSync(dir, { withFileTypes: true })
    .filter(d => d.isFile() && /\.pdf$/i.test(d.name) && !d.name.startsWith('.'))
    .map(d => path.join(dir, d.name))
    .filter(f => Date.now() - fs.statSync(f).mtimeMs > 60000) // Scanner fertig?
    .slice(0, 20)
  for (const file of files) {
    const name = path.basename(file)
    try {
      const pdf = fs.readFileSync(file)
      if (pdf.subarray(0, 5).toString() !== '%PDF-') throw new Error('keine PDF-Datei')
      const hash = crypto.createHash('sha256').update(pdf).digest('hex')
      const msgid = `<scan-${hash.slice(0, 24)}@mail-sortierer.invalid>`
      const info = await analyze(cfg, { pdf, pdfName: name, from: 'Scanner', subject: name, mailDate: fs.statSync(file).mtime })
      if (info.risk.length) {
        insertInvoice({ source: 'scan', msgid, from_addr: 'Scanner', subject: name, ...storeDocs(info), brand: info.brand, supplier: info.supplier, number: info.number, inv_date: info.date, content: info.content, text_snippet: info.snippet, amount: info.amount, status: 'blocked', risk: info.risk, hint: 'Datei gesperrt: ' + info.risk.join('; ') })
        moveScanFile(dir, file, 'gesperrt')
        log('warn', `Scan ${name} gesperrt: ${info.risk.join('; ')}`)
        continue
      }
      const docs = storeDocs(info)
      const key = info.order ? null : dedupeKey(info)
      const dup = findDuplicate(docs.file_hash, key)
      const base = {
        source: 'scan', msgid, from_addr: 'Scanner', subject: name, supplier: info.supplier, number: info.number, inv_date: info.date, content: info.content, text_snippet: info.snippet, content: info.content, text_snippet: info.snippet,
        amount: info.amount, currency: info.currency, einvoice: info.einvoice, ...docs, dedupe: key, brand: info.brand,
        suggestion: suggestionFor(info, ''), hint: info.isInvoice ? info.reason : 'KI: eher keine Rechnung – bitte prüfen'
      }
      if (dup) {
        insertInvoice({ ...base, status: 'duplicate', hint: `doppelt – schon vorhanden (#${dup.id})` })
        moveScanFile(dir, file, 'doppelt')
        log('info', `Scan ${name} ist doppelt (schon #${dup.id})`)
        continue
      }
      const tc = await ctx.client(target)
      const dest = await ensurePath(tc, info.order ? orderParts(cfg, info.ym) : monthParts(cfg, info.ym))
      const subject = `Scan: ${[info.supplier, info.number].filter(Boolean).join(' ') || name}`
      const mail = buildScanMail({
        to: target.user, subject, fileName: name, pdf, msgid, date: new Date(),
        text: `Eingescannt am ${new Date().toLocaleString('de-DE', { timeZone: 'Europe/Berlin' })}\nDatei: ${name}\nLieferant: ${info.supplier || '-'}\nRechnungsnummer: ${info.number || '-'}\nDatum: ${info.date || '-'}\nBetrag: ${info.amount != null ? info.amount.toFixed(2).replace('.', ',') + ' ' + info.currency : '-'}\n`
      })
      const closed = yearClosed(info.ym, cfg)
      const uid = await appendMessage(tc, dest, mail, cfg.invoices.flagOpen && !closed && !info.order ? ['\\Flagged'] : [])
      insertInvoice({ ...base, account_id: target.id, folder: dest, uid, same_message: 1, status: info.order ? 'order' : closed ? 'archived' : 'open', ...(info.order ? { hint: 'Auftragsbestätigung – nichts zu prüfen' } : {}) })
      moveScanFile(dir, file, info.ym)
      stats.scans = (stats.scans || 0) + 1
      log('info', `Scan abgelegt: ${name} → ${dest}`)
    } catch (e) {
      if (/Ollama/.test(e.message)) throw e // KI weg → später erneut
      log('error', `Scan ${name}: ${e.message}`)
      try { moveScanFile(dir, file, 'fehler') } catch { /* egal */ }
    }
  }
}

// ---------- Aktionen ----------

async function withTarget (fn) {
  const t = collecting()
  if (!t) throw new Error('Kein Sammel-Postfach für Rechnungen eingestellt.')
  return withClient(t, fn)
}

// Ablage-Mail im Sammel-Postfach in einen anderen Ordner bringen, Fähnchen setzen/entfernen
async function relocate (client, inv, parts, flagged) {
  if (!inv.folder) return {}
  const dest = parts ? await ensurePath(client, parts) : inv.folder
  const lock = await client.getMailboxLock(inv.folder)
  try {
    let uid = inv.uid
    const ok = uid && ((await client.search({ uid: String(uid) }, { uid: true })) || []).length
    if (!ok) uid = (await findByMsgId(client, inv.msgid))[0]
    if (!uid) throw new Error(`Ablage-Mail nicht mehr in „${inv.folder}“ gefunden`)
    if (flagged === true) await client.messageFlagsAdd(String(uid), ['\\Flagged'], { uid: true })
    if (flagged === false) await client.messageFlagsRemove(String(uid), ['\\Flagged'], { uid: true })
    if (dest === inv.folder) return { folder: dest, uid }
    const newUid = await moveMessage(client, uid, dest)
    return { folder: dest, uid: newUid }
  } finally { lock.release() }
}

export async function lexwareUpload (inv) {
  const cfg = getConfig()
  if (inv.status === 'blocked') throw new Error('Gesperrter Beleg – wird nicht weitergegeben.')
  const key = getSecret('lexwareKey')
  if (!key) throw new Error('Kein Lexware-API-Schlüssel hinterlegt (Einstellungen → Rechnungen).')
  const p = filePath(inv.file)
  if (!p || !fs.existsSync(p)) throw new Error('Kein Beleg vorhanden – Rechnung z. B. im Kundenkonto des Lieferanten herunterladen und einscannen.')
  const buf = fs.readFileSync(p)
  if (buf.length > 5 * 1024 * 1024) throw new Error('Datei größer als 5 MB – Lexware nimmt sie nicht an. Bitte direkt in Lexware hochladen.')
  const type = /\.xml$/i.test(p) ? 'application/xml' : /\.png$/i.test(p) ? 'image/png' : /\.jpe?g$/i.test(p) ? 'image/jpeg' : 'application/pdf'
  const fd = new FormData()
  fd.append('file', new Blob([buf], { type }), inv.file_name || path.basename(p))
  fd.append('type', 'voucher')
  const base = String(cfg.invoices.lexwareUrl || 'https://api.lexware.io').replace(/\/+$/, '')
  for (let attempt = 0; attempt < 3; attempt++) {
    const r = await fetch(base + '/v1/files', { method: 'POST', headers: { Authorization: `Bearer ${key}`, Accept: 'application/json' }, body: fd })
    if (r.status === 429) { await new Promise(res => setTimeout(res, 1500 * (attempt + 1))); continue }
    const text = await r.text()
    if (!r.ok) throw new Error(`Lexware ${r.status}: ${text.slice(0, 300) || r.statusText}`)
    try { return JSON.parse(text).id || '' } catch { return '' }
  }
  throw new Error('Lexware: zu viele Anfragen – später erneut versuchen.')
}

export async function lexwareTest () {
  const cfg = getConfig()
  const key = getSecret('lexwareKey')
  if (!key) throw new Error('Kein Schlüssel hinterlegt.')
  const r = await fetch(String(cfg.invoices.lexwareUrl).replace(/\/+$/, '') + '/v1/profile', { headers: { Authorization: `Bearer ${key}`, Accept: 'application/json' } })
  const t = await r.text()
  if (!r.ok) throw new Error(`Lexware ${r.status}: ${t.slice(0, 200)}`)
  const j = JSON.parse(t)
  return j.companyName || j.organizationName || 'verbunden'
}

export async function toAccounting (ids) {
  if (!licensedFull()) throw new Error('Ohne gültige Lizenz geht nichts an Lexware (Einstellungen → Lizenz).')
  if (!getConfig().features.lexware) throw new Error('Lexware ist für dieses Konto nicht freigegeben.')
  const done = []; const errors = []
  const list = ids.map(getInvoice).filter(i => i && ['open', 'error', 'private', 'noinvoice'].includes(i.status))
  if (!list.length) return { done, errors }
  await withTarget(async (client) => {
    for (const inv of list) {
      try {
        const lexId = await lexwareUpload(inv)
        let loc = {}
        try {
          const cfg = getConfig()
          loc = await relocate(client, inv, inv.status === 'open' || inv.status === 'error' ? null : monthParts(cfg, ymOf(inv.inv_date, inv.created_at)), false)
        } catch (e) { log('warn', `Rechnung #${inv.id} an Lexware gesendet, aber Fähnchen nicht entfernt: ${e.message}`) }
        upd(inv.id, { status: 'sent', lexware_id: lexId, decided_at: now(), error: null, ...loc })
        invLearn({ ...inv, ...getInvoice(inv.id) }, 'business')
        done.push(inv.id)
      } catch (e) {
        upd(inv.id, { error: String(e.message).slice(0, 300) })
        errors.push(`#${inv.id}: ${e.message}`)
      }
    }
  })
  if (done.length) log('info', `${done.length} Rechnung(en) an Lexware Office gesendet`)
  return { done, errors }
}

export async function markPrivate (ids) {
  const cfg = getConfig()
  const list = ids.map(getInvoice).filter(i => i && ['open', 'error', 'noinvoice'].includes(i.status))
  await withTarget(async (client) => {
    for (const inv of list) {
      const ym = ymOf(inv.inv_date, inv.created_at)
      const loc = await relocate(client, inv, [cfg.invoices.root, cfg.invoices.privateName, ym.slice(0, 4)], false)
      upd(inv.id, { status: 'private', decided_at: now(), error: null, ...loc })
      invLearn(getInvoice(inv.id), 'private')
    }
  })
  return list.length
}

export async function markNoInvoice (ids) {
  const cfg = getConfig()
  const list = ids.map(getInvoice).filter(i => i && ['open', 'error', 'private', 'duplicate'].includes(i.status))
  await withTarget(async (client) => {
    for (const inv of list) {
      const loc = inv.status === 'duplicate' ? {} : await relocate(client, inv, [cfg.invoices.root, cfg.invoices.noInvoiceName], false)
      upd(inv.id, { status: 'noinvoice', decided_at: now(), error: null, ...loc })
      invLearn(getInvoice(inv.id), 'noinvoice')
    }
  })
  return list.length
}

export async function reopen (ids) {
  const cfg = getConfig()
  const list = ids.map(getInvoice).filter(i => i && ['private', 'noinvoice', 'order'].includes(i.status))
  // Von Hand aus „Auftragsbestätigung“ zurückgeholt → automatische Erkennung lässt diese Einträge in Ruhe
  const keep = new Set(kvGet('orderKeepOpen', []))
  for (const i of list) if (i.status === 'order') keep.add(i.id)
  kvSet('orderKeepOpen', [...keep].slice(-2000))
  await withTarget(async (client) => {
    for (const inv of list) {
      const loc = await relocate(client, inv, monthParts(cfg, ymOf(inv.inv_date, inv.created_at)), cfg.invoices.flagOpen)
      upd(inv.id, { status: 'open', decided_at: null, ...loc })
    }
  })
  return list.length
}

// Gesperrten Beleg bewusst freigeben (nur Lexware-Versand möglich, Vorschau bleibt gesperrt)
export function release (ids) {
  let n = 0
  for (const inv of ids.map(getInvoice).filter(i => i && i.status === 'blocked' && i.file)) {
    upd(inv.id, { status: 'open', suggestion: inv.brand ? 'business' : 'check', hint: 'trotz Warnung freigegeben' })
    log('warn', `Gesperrter Beleg #${inv.id} (${inv.supplier || inv.from_addr}) von Hand freigegeben`)
    n++
  }
  return n
}

// Angaben von Hand korrigieren; anderer Monat → Ablage-Mail wandert mit
export async function editInvoice (id, f) {
  const inv = getInvoice(id)
  if (!inv) throw new Error('Rechnung nicht gefunden')
  const date = /^\d{4}-\d{2}-\d{2}$/.test(f.inv_date) ? f.inv_date : ''
  const amount = f.amount === '' || f.amount == null ? null : Number(String(f.amount).replace(/\./g, '').replace(',', '.'))
  const next = {
    supplier: String(f.supplier || '').slice(0, 120), number: String(f.number || '').slice(0, 80), inv_date: date, content: String(f.content ?? inv.content ?? '').slice(0, 120),
    amount: Number.isFinite(amount) ? Math.round(amount * 100) / 100 : null
  }
  if (f.brand !== undefined) next.brand = companyList(cfg0()).includes(f.brand) ? f.brand : null
  next.dedupe = dedupeKey(next)
  const cfg = getConfig()
  const oldYm = ymOf(inv.inv_date, inv.created_at); const newYm = ymOf(next.inv_date, inv.created_at)
  let loc = {}
  if (oldYm !== newYm && ['open', 'sent', 'error'].includes(inv.status) && inv.folder) {
    loc = await withTarget(client => relocate(client, inv, monthParts(cfg, newYm), undefined))
  }
  if (inv.status === 'archived' && !yearClosed(newYm, cfg)) next.status = 'open'
  else if (['open', 'error'].includes(inv.status) && yearClosed(newYm, cfg)) next.status = 'archived'
  upd(inv.id, { ...next, ...loc })
  // Geänderte Angaben = Lernbeispiel (Lieferantenname, Firma, Inhalt … beim nächsten Mal so)
  const changed = ['supplier', 'number', 'inv_date', 'amount', 'content', 'brand'].some(k => next[k] !== undefined && String(next[k] ?? '') !== String(inv[k] ?? ''))
  if (changed) {
    const cur = getInvoice(inv.id)
    invLearn(cur, cur.brand ? 'business' : cur.status === 'private' ? 'private' : 'edit')
    if (cur.brand && ['open', 'error'].includes(cur.status)) upd(cur.id, { suggestion: 'business' })
  }
}

// Mail wurde in der Oberfläche von „Rechnungen“ weg korrigiert
export async function dropForMail (mailId) {
  const list = db.prepare("SELECT * FROM invoices WHERE mail_id = ? AND status IN ('open', 'error', 'private')").all(mailId)
  for (const inv of list) {
    if (inv.same_message) upd(inv.id, { status: 'noinvoice', decided_at: now(), hint: 'als Mail anders einsortiert' })
    else await markNoInvoice([inv.id])
  }
}

const cfg0 = () => getConfig()
export const STATUS = { open: 'Offen', order: 'Auftragsbestätigung', nodoc: 'Ohne Beleg', sent: 'In Lexware', private: 'Privat', noinvoice: 'Keine Rechnung', duplicate: 'Doppelt', error: 'Fehler', blocked: 'Gesperrt', archived: 'Jahr abgeschlossen' }

// Von Hand als Auftragsbestätigung ablegen (Rechnungen/Auftragsbestätigungen/JJJJ, ohne Fähnchen; die KI lernt mit)
export async function markOrder (ids) {
  const cfg = getConfig()
  const list = ids.map(getInvoice).filter(i => i && ['open', 'error', 'noinvoice', 'nodoc', 'private'].includes(i.status))
  await withTarget(async (client) => {
    for (const inv of list) {
      const loc = await relocate(client, inv, orderParts(cfg, ymOf(inv.inv_date, inv.created_at)), false)
      upd(inv.id, { status: 'order', decided_at: now(), error: null, dedupe: null, hint: 'Auftragsbestätigung', ...loc })
      invLearn(getInvoice(inv.id), 'order')
    }
  })
  return list.length
}

// Offene Einträge, die schon am Betreff/Dateinamen/Belegtext als Auftragsbestätigung erkennbar sind, umsortieren (läuft vor jedem Durchlauf)
export async function applyOrders () {
  const cfg = getConfig()
  const keepOpen = new Set(kvGet('orderKeepOpen', []))
  const rows = db.prepare("SELECT * FROM invoices WHERE status IN ('open', 'error') AND COALESCE(einvoice, '') = ''").all()
    .filter(r => !keepOpen.has(r.id) && isOrderConfirmation({ subject: r.subject, fileName: r.file_name, text: r.text_snippet }))
  if (!rows.length) return 0
  let n = 0
  try {
    await withTarget(async (client) => {
      for (const r of rows) {
        const loc = await relocate(client, r, orderParts(cfg, ymOf(r.inv_date, r.created_at)), false).catch(() => null)
        if (!loc) continue
        upd(r.id, { status: 'order', decided_at: now(), error: null, dedupe: null, hint: 'Auftragsbestätigung – nichts zu prüfen', ...loc })
        n++
      }
    })
  } catch (e) { log('warn', 'Auftragsbestätigungen umsortieren: ' + e.message) }
  if (n) log('info', `${n} Auftragsbestätigung(en) aus der Prüfliste genommen und abgelegt`)
  return n
}

// Offene Rechnungen ohne Beleg brauchen keine Prüfung → Status „Ohne Beleg“, Fähnchen weg (läuft vor jedem Durchlauf)
export async function applyNoDoc () {
  const rows = db.prepare("SELECT * FROM invoices WHERE status IN ('open', 'error') AND COALESCE(file, '') = '' AND COALESCE(xml_file, '') = ''").all()
  if (!rows.length) return 0
  for (const r of rows) upd(r.id, { status: 'nodoc', decided_at: now(), hint: 'kein Beleg in der Mail – nichts zu prüfen', error: null })
  try {
    await withTarget(async (client) => { for (const r of rows) await relocate(client, r, null, false).catch(() => {}) })
  } catch (e) { log('warn', 'Fähnchen konnten nicht entfernt werden: ' + e.message) }
  log('info', `${rows.length} Rechnung(en) ohne Beleg aus der Prüfliste genommen`)
  return rows.length
}

// Nach Änderung von „ab Jahr“: offene Rechnungen älterer Jahre abschließen (Fähnchen weg) bzw. wieder öffnen
export async function applyYearSetting () {
  const cfg = getConfig()
  const ymRow = (r) => ymOf(r.inv_date, r.created_at)
  const toClose = db.prepare("SELECT * FROM invoices WHERE status IN ('open', 'error')").all().filter(r => yearClosed(ymRow(r), cfg))
  const toOpen = db.prepare("SELECT * FROM invoices WHERE status = 'archived'").all().filter(r => !yearClosed(ymRow(r), cfg))
  if (!toClose.length && !toOpen.length) return { closed: 0, opened: 0 }
  for (const r of toClose) upd(r.id, { status: 'archived', decided_at: now() })
  for (const r of toOpen) upd(r.id, { status: 'open', decided_at: null })
  // Fähnchen in Outlook nachziehen (Fehler hier sind nicht schlimm – nur Optik)
  try {
    await withTarget(async (client) => {
      for (const r of toClose) await relocate(client, r, null, false).catch(() => {})
      if (cfg.invoices.flagOpen) for (const r of toOpen) await relocate(client, r, null, true).catch(() => {})
    })
  } catch (e) { log('warn', 'Fähnchen konnten nicht angepasst werden: ' + e.message) }
  log('info', `Rechnungen ab ${cfg.invoices.fromYear || 'allen Jahren'}: ${toClose.length} abgeschlossen, ${toOpen.length} wieder offen`)
  return { closed: toClose.length, opened: toOpen.length }
}
