// Sicherheit: gefährliche Anhänge, riskante PDFs, Phishing-Merkmale, Spam-Sperrlisten.
// Grundsatz: Anhänge werden NIE geöffnet oder ausgeführt – nur als Bytes untersucht.
import zlib from 'node:zlib'
import dns from 'node:dns/promises'
import net from 'node:net'

// ---------- Anhänge ----------

const DANGEROUS_EXT = new Set(('exe com scr pif bat cmd vbs vbe js jse wsf wsh hta msi msp msc cpl jar ps1 psm1 reg lnk inf scf url ' +
  'iso img vhd vhdx one onepkg chm application gadget appx appxbundle msix dll sys apk dmg pkg app sh').split(' '))
const MACRO_EXT = new Set('docm dotm xlsm xltm xlam pptm potm ppam sldm'.split(' '))
const HTML_EXT = new Set('html htm shtml xhtml svg mht mhtml'.split(' '))
const ARCHIVE_EXT = new Set('zip rar 7z gz tgz tar bz2 xz cab arj lzh ace z'.split(' '))

const extOf = (n) => { const m = String(n || '').toLowerCase().match(/\.([a-z0-9]{1,12})$/); return m ? m[1] : '' }

// ZIP-Inhaltsverzeichnis lesen (ohne Entpacken)
export function zipEntries (buf) {
  const out = []
  if (!buf || buf.length < 22) return out
  const min = Math.max(0, buf.length - 66000)
  let eocd = -1
  for (let i = buf.length - 22; i >= min; i--) if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break }
  if (eocd < 0) return out
  let p = buf.readUInt32LE(eocd + 16)
  const total = buf.readUInt16LE(eocd + 10)
  for (let n = 0; n < Math.min(total, 2000) && p + 46 <= buf.length; n++) {
    if (buf.readUInt32LE(p) !== 0x02014b50) break
    const flags = buf.readUInt16LE(p + 8)
    const nl = buf.readUInt16LE(p + 28); const xl = buf.readUInt16LE(p + 30); const cl = buf.readUInt16LE(p + 32)
    out.push({ name: buf.subarray(p + 46, p + 46 + nl).toString('utf8'), encrypted: !!(flags & 1) })
    p += 46 + nl + xl + cl
  }
  return out
}

// Ein Anhang → { danger, warn } (Text der Gründe)
export function scanAttachment ({ filename, contentType, content }) {
  const name = String(filename || '')
  const ext = extOf(name)
  const head = content && content.length ? content.subarray(0, 8) : null
  const r = { name, danger: null, warn: null }
  if (/\.(pdf|docx?|xlsx?|jpe?g|png|txt)\.[a-z0-9]{2,5}$/i.test(name) && DANGEROUS_EXT.has(ext)) r.danger = `getarnter Anhang „${name}“ (doppelte Endung)`
  else if (DANGEROUS_EXT.has(ext)) r.danger = `ausführbarer Anhang „${name}“`
  else if (MACRO_EXT.has(ext)) r.danger = `Office-Datei mit Makros „${name}“`
  else if (HTML_EXT.has(ext) || /text\/html/i.test(contentType || '') && name) r.danger = `HTML-Anhang „${name}“ (typisch für gefälschte Anmeldeseiten)`
  if (!r.danger && head) {
    if (head.subarray(0, 2).toString('latin1') === 'MZ') r.danger = `Programmdatei getarnt als „${name}“`
    else if (ext === 'pdf' && head.subarray(0, 5).toString('latin1') !== '%PDF-' && content.length > 1024) r.danger = `„${name}“ ist keine echte PDF-Datei`
    else if (/^d0cf11e0/i.test(head.toString('hex').slice(0, 8)) && /^(doc|xls|ppt)$/.test(ext)) r.warn = `alte Office-Datei „${name}“ (kann Makros enthalten)`
  }
  if (!r.danger && (ARCHIVE_EXT.has(ext) || (head && head.readUInt32LE?.(0) === 0x04034b50 && !/^(docx|xlsx|pptx|odt|ods)$/.test(ext)))) {
    const entries = content ? zipEntries(content) : []
    const bad = entries.find(e => DANGEROUS_EXT.has(extOf(e.name)) || MACRO_EXT.has(extOf(e.name)) || HTML_EXT.has(extOf(e.name)))
    if (bad) r.danger = `Archiv „${name}“ enthält „${bad.name}“`
    else if (entries.some(e => e.encrypted)) r.danger = `Archiv „${name}“ mit Passwort (Virenscanner können es nicht prüfen)`
    else if (ARCHIVE_EXT.has(ext) && !entries.length) r.warn = `Archiv „${name}“ (Inhalt nicht prüfbar)`
  }
  if (!r.danger && /^(docx|xlsx|pptx)$/.test(ext) && content && zipEntries(content).some(e => /vbaProject\.bin$/i.test(e.name))) r.danger = `Office-Datei mit Makros „${name}“`
  return r
}

// Alle (FlateDecode-)Streams einer PDF entpacken – für Prüfung und eingebettete E-Rechnung
export function * pdfStreams (pdf, max = 400) {
  const s = pdf.toString('latin1')
  const re = /<<((?:(?!>>\s*stream)[\s\S]){0,2000})>>\s*stream\r?\n/g
  let m; let n = 0
  while ((m = re.exec(s)) && n++ < max) {
    const start = m.index + m[0].length
    const end = s.indexOf('endstream', start)
    if (end < 0) break
    if (end - start > 8 * 1024 * 1024) continue
    let data = pdf.subarray(start, end)
    if (/FlateDecode/.test(m[1])) {
      try { data = zlib.inflateSync(data, { finishFlush: zlib.constants.Z_SYNC_FLUSH, maxOutputLength: 20 * 1024 * 1024 }) } catch { continue }
    }
    yield { dict: m[1], data }
  }
}

const EINVOICE_NAME = /factur-x|zugferd|xrechnung|order-x/i

// Riskante PDF-Bestandteile (JavaScript, Programmstart, fremde eingebettete Dateien, Formular-Versand)
export function pdfRisk (pdf) {
  if (!pdf || pdf.subarray(0, 5).toString('latin1') !== '%PDF-') return ['keine gültige PDF-Datei']
  const reasons = new Set()
  const check = (t) => {
    if (/\/(JavaScript|JS)\s*[(<[/]/.test(t) || /\/S\s*\/JavaScript/.test(t)) reasons.add('enthält JavaScript')
    if (/\/Launch\b/.test(t)) reasons.add('will ein Programm starten (/Launch)')
    if (/\/SubmitForm\b/.test(t)) reasons.add('schickt Formulardaten ins Internet')
    if (/\/RichMedia\b/.test(t)) reasons.add('enthält eingebettete Medien (Flash)')
    if (/\/XFA\b/.test(t)) reasons.add('enthält XFA-Formular')
    for (const f of t.matchAll(/\/Type\s*\/Filespec[\s\S]{0,300}?\/(?:UF|F)\s*\(([^)]{1,200})\)/g)) {
      if (!EINVOICE_NAME.test(f[1])) reasons.add(`enthält versteckte Datei „${f[1]}“`)
    }
  }
  check(pdf.toString('latin1'))
  let n = 0
  for (const st of pdfStreams(pdf, 300)) {
    if (/ObjStm/.test(st.dict) || n++ < 50) check(st.data.toString('latin1').slice(0, 2_000_000))
  }
  return [...reasons]
}

// ---------- Phishing ----------

// Häufig gefälschte Absender: Name → echte Domains
const BRANDS = {
  paypal: ['paypal.com', 'paypal.de', 'paypal-mail.com'],
  amazon: ['amazon.de', 'amazon.com', 'amazon.co.uk', 'amazonses.com', 'marketplace.amazon.de'],
  dhl: ['dhl.de', 'dhl.com', 'deutschepost.de', 'dhl-news.com'],
  sparkasse: ['sparkasse.de', 's-kundenservice.de', 'sparkassen-finanzportal.de'],
  volksbank: ['vr.de', 'volksbank.de', 'vrbank.de'],
  commerzbank: ['commerzbank.de', 'commerzbank.com'],
  'deutsche bank': ['db.com', 'deutsche-bank.de'],
  postbank: ['postbank.de'],
  ing: ['ing.de', 'ing.com'],
  n26: ['n26.com'],
  telekom: ['telekom.de', 't-online.de', 'telekom.com'],
  vodafone: ['vodafone.de', 'vodafone.com'],
  microsoft: ['microsoft.com', 'microsoftonline.com', 'office.com', 'outlook.com', 'live.com', 'sharepoint.com'],
  apple: ['apple.com', 'icloud.com', 'email.apple.com'],
  ebay: ['ebay.de', 'ebay.com', 'members.ebay.de'],
  netflix: ['netflix.com'],
  lexware: ['lexware.de', 'lexoffice.de', 'lexware.io', 'haufe.com'],
  alfahosting: ['alfahosting.de'],
  dpd: ['dpd.de', 'dpd.com'],
  ups: ['ups.com'],
  hermes: ['myhermes.de', 'hermesworld.com'],
  gls: ['gls-group.eu', 'gls-pakete.de'],
  google: ['google.com', 'gmail.com', 'accounts.google.com'],
  facebook: ['facebook.com', 'facebookmail.com', 'meta.com'],
  instagram: ['instagram.com', 'mail.instagram.com'],
  whatsapp: ['whatsapp.com'],
  klarna: ['klarna.com', 'klarna.de'],
  elster: ['elster.de'],
  finanzamt: ['finanzamt.de', 'elster.de', 'bzst.de'],
  github: ['github.com'],
  sendcloud: ['sendcloud.com', 'sendcloud.de'],
  mastercard: ['mastercard.com', 'mastercard.de'],
  visa: ['visa.com', 'visa.de'],
  adobe: ['adobe.com'],
  dropbox: ['dropbox.com', 'dropboxmail.com'],
  docusign: ['docusign.net', 'docusign.com']
}
export function brandList (extra) {
  const b = { ...BRANDS }
  for (const line of String(extra || '').split('\n')) {
    const m = line.match(/^\s*([^=]{2,40})=\s*(.+)$/)
    if (m) b[m[1].trim().toLowerCase()] = m[2].split(/[,\s]+/).map(x => x.trim().toLowerCase()).filter(Boolean)
  }
  return b
}

const SHORTENERS = new Set('bit.ly tinyurl.com t.co goo.gl is.gd cutt.ly rebrand.ly ow.ly buff.ly shorturl.at rb.gy t.ly tiny.cc s.id lnkd.in'.split(' '))
const MULTI_TLD = new Set('co.uk com.au co.at or.at gv.at co.jp com.br co.nz'.split(' '))
export function baseDomain (host) {
  const h = String(host || '').toLowerCase().replace(/\.$/, '')
  const p = h.split('.')
  if (p.length <= 2) return h
  return MULTI_TLD.has(p.slice(-2).join('.')) ? p.slice(-3).join('.') : p.slice(-2).join('.')
}
const belongsTo = (host, domains) => domains.some(d => host === d || host.endsWith('.' + d))

function lev (a, b) {
  if (Math.abs(a.length - b.length) > 2) return 9
  const d = Array.from({ length: a.length + 1 }, (_, i) => [i])
  for (let j = 1; j <= b.length; j++) d[0][j] = j
  for (let i = 1; i <= a.length; i++) for (let j = 1; j <= b.length; j++) d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1))
  return d[a.length][b.length]
}
const unconfuse = (s) => s.replace(/rn/g, 'm').replace(/vv/g, 'w').replace(/0/g, 'o').replace(/1/g, 'l').replace(/3/g, 'e').replace(/5/g, 's').replace(/[il|]/g, 'l')

// Sieht die Domain aus wie eine bekannte Marke, ist es aber nicht?
export function lookalike (host, brands) {
  const h = String(host || '').toLowerCase()
  if (!h) return null
  const all = Object.entries(brands)
  for (const [, domains] of all) if (belongsTo(h, domains)) return null
  if (h.includes('xn--')) return `Domain mit Sonderzeichen-Trick (${h})`
  const label = baseDomain(h).split('.')[0]
  const tokens = label.split('-').filter(Boolean)
  for (const [name, domains] of all) {
    for (const d of domains) {
      const dl = d.split('.')[0]
      if (dl.length < 3) continue
      // Tippfehler-Domain (paypa1, amaz0n) bzw. vertauschte Zeichen (dhI statt dhl)
      if (dl.length >= 4 && label !== dl && (lev(label, dl) <= (dl.length > 6 ? 2 : 1) || unconfuse(label) === unconfuse(dl))) return `nachgemachte Domain ${h} (ähnlich ${d})`
      if (tokens.some(t => t !== dl && unconfuse(t) === unconfuse(dl))) return `nachgemachte Domain ${h} (ähnlich ${d})`
    }
    const key = name.replace(/\s+/g, '')
    if (key.length >= 3 && (tokens.includes(key) || (key.length >= 5 && label.includes(key))) && tokens.length > 1 &&
      /(secure|login|konto|verify|verif|support|service|update|account|kunden|sicher|pay|bank|zahlung|paket|post|sendung|versand|track|online|info|center|portal|hilfe|help)/.test(label)) return `Domain gibt sich als ${name} aus (${h})`
  }
  return null
}

function linksOf (html) {
  const out = []
  for (const m of String(html || '').matchAll(/<a\b[^>]*\bhref\s*=\s*["']?([^"'\s>]+)["']?[^>]*>([\s\S]{0,300}?)<\/a>/gi)) {
    out.push({ href: m[1].replace(/&amp;/g, '&'), text: m[2].replace(/<[^>]+>/g, ' ').replace(/&nbsp;/g, ' ').replace(/\s+/g, ' ').trim() })
    if (out.length > 300) break
  }
  return out
}
const hostOf = (u) => { try { return new URL(u).hostname.toLowerCase() } catch { return '' } }

const URGENT = /(konto|zugang|account|karte)[^.]{0,40}(gesperrt|eingeschränkt|deaktiviert|ausgesetzt|suspend)|ungewöhnliche (aktivität|anmeldung)|innerhalb von (24|48) stunden|letzte (warnung|mahnung|erinnerung)|sofort(ige)? (handeln|bestätigung)|verify your|unusual (activity|sign)|account (locked|suspended)|zahlung (fehlgeschlagen|abgelehnt)|paket (konnte nicht|wird zurück)/i
const CREDS = /passwort|kennwort|zugangsdaten|anmeldedaten|\btan\b|\bpin\b|kreditkart|iban|sicherheitsfrage|login|einloggen|anmelden|password|credentials|bestätigen sie (ihre|ihr) (daten|konto|identität)|daten (aktualisieren|bestätigen)/i

/**
 * Bewertung einer Mail. m: { from_addr, from_name, domain, subject, text, html, headers (Map), attachments [{filename, contentType, content}], attNames [] }
 * opts: { brands, trusted, known (Kontakt/oft gesehen), contentKnownSender }
 * → { score, reasons: [{p, t}], dangerous, spamHeader }
 */
export function phishCheck (m, opts = {}) {
  const reasons = []
  const add = (p, t) => { if (!reasons.some(r => r.t === t)) reasons.push({ p, t }) }
  const brands = opts.brands || BRANDS
  const h = m.headers || new Map()
  const hv = (k) => { const v = h.get(k); return v == null ? '' : (typeof v === 'string' ? v : (v.text || v.value || JSON.stringify(v))) }
  let dangerous = false

  // Anhänge
  for (const a of m.attachments || []) {
    const r = scanAttachment(a)
    if (r.danger) { add(70, r.danger); dangerous = true } else if (r.warn) add(15, r.warn)
  }
  for (const n of m.attNames || []) {
    if ((m.attachments || []).some(a => a.filename === n)) continue
    const r = scanAttachment({ filename: n })
    if (r.danger) { add(70, r.danger); dangerous = true } else if (r.warn) add(15, r.warn)
  }

  // Absender-Prüfungen des Mailservers
  const auth = String(hv('authentication-results')).toLowerCase()
  if (/dmarc=fail/.test(auth)) add(40, 'Absender-Prüfung DMARC fehlgeschlagen')
  if (/spf=fail/.test(auth)) add(20, 'SPF fehlgeschlagen (Server darf für diese Domain nicht senden)')
  else if (/spf=softfail/.test(auth)) add(8, 'SPF unsicher (softfail)')
  if (/dkim=fail/.test(auth)) add(15, 'DKIM-Signatur ungültig')

  // Spam-Kennzeichnung des eigenen Mailservers
  const spamFlag = /^\s*yes/i.test(hv('x-spam-flag')) || /^\s*yes/i.test(hv('x-spam-status'))
  const spamScore = Number((hv('x-spam-score') || hv('x-spam-status')).match(/(?:score=)?(-?\d+(?:\.\d+)?)/)?.[1])
  if (spamFlag) add(20, 'Mailserver hat die Mail als Spam markiert')

  const fromHost = String(m.domain || '').toLowerCase()
  const disp = String(m.from_name || '').toLowerCase()

  // Anzeigename gibt sich als bekannte Marke aus, Domain passt nicht
  for (const [name, domains] of Object.entries(brands)) {
    if (name.length >= 3 && new RegExp(`(^|[^a-zäöü])${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}([^a-zäöü]|$)`).test(disp) && fromHost && !belongsTo(fromHost, domains)) {
      add(35, `Absender nennt sich „${m.from_name}“, schreibt aber von ${fromHost}`); break
    }
  }
  // Anzeigename enthält eine andere Mailadresse
  const dispMail = disp.match(/[a-z0-9._%+-]+@([a-z0-9.-]+\.[a-z]{2,})/)
  if (dispMail && baseDomain(dispMail[1]) !== baseDomain(fromHost)) add(25, `Anzeigename zeigt eine andere Adresse (${dispMail[0]})`)
  const look = lookalike(fromHost, brands)
  if (look) add(40, look)

  // Antwortadresse auf eine fremde Domain
  const reply = String(hv('reply-to')).toLowerCase().match(/[a-z0-9._%+-]+@([a-z0-9.-]+\.[a-z]{2,})/)
  if (reply && fromHost && baseDomain(reply[1]) !== baseDomain(fromHost) && !/(gmail|gmx|web|outlook|t-online|yahoo)\./.test(reply[1])) add(12, `Antworten gehen an eine andere Domain (${reply[1]})`)

  // Links
  const links = linksOf(m.html)
  const linkHosts = new Set()
  for (const l of links) {
    if (!/^https?:/i.test(l.href)) continue
    const lh = hostOf(l.href)
    if (!lh) continue
    linkHosts.add(lh)
    if (net.isIP(lh.replace(/^\[|\]$/g, ''))) add(30, `Link auf eine IP-Adresse (${lh})`)
    const shown = l.text.match(/(?:https?:\/\/)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:\/|\s|$)/i)
    if (shown && baseDomain(shown[1].toLowerCase()) !== baseDomain(lh) && !SHORTENERS.has(lh)) add(30, `Link zeigt „${shown[1]}“, führt aber zu ${lh}`)
    if (SHORTENERS.has(lh)) add(10, `Kurz-Link verschleiert das Ziel (${lh})`)
    const lk = lookalike(lh, brands)
    if (lk) add(40, 'Link auf ' + lk)
    if (/\.(exe|scr|js|vbs|zip|rar|7z|iso|img|hta|apk|msi|bat|cmd|lnk)$/i.test(new URL(l.href).pathname)) add(25, `Link lädt eine Datei herunter (${lh})`)
  }
  m.linkHosts = [...linkHosts].slice(0, 30)

  // Druck + Datenabfrage
  const body = `${m.subject || ''}\n${m.text || ''}`
  if (URGENT.test(body) && CREDS.test(body)) add(25, 'setzt unter Druck und fragt nach Zugangsdaten/Zahlungsdaten')
  else if (URGENT.test(body) && links.length) add(8, 'drängt zu schnellem Handeln')

  // Bekannte/vertraute Absender abschwächen (gefährliche Anhänge bleiben gefährlich)
  let score = reasons.reduce((a, r) => a + r.p, 0)
  if (opts.known && !dangerous) score = Math.max(0, score - 30)
  if (opts.trusted && !dangerous) score = 0
  return { score, reasons: reasons.sort((a, b) => b.p - a.p), dangerous, spamHeader: spamFlag || (Number.isFinite(spamScore) && spamScore >= 8), linkHosts: m.linkHosts }
}

// ---------- Spam-Sperrlisten (DNS) ----------
// Es gehen nur IP-Adressen bzw. Domains an die Listenbetreiber, nie Mailinhalte.

export const DEFAULT_IP_LISTS = 'zen.spamhaus.org\nbl.spamcop.net'
export const DEFAULT_DOMAIN_LISTS = 'dbl.spamhaus.org\nmulti.surbl.org'
const cache = new Map()

// DNS-Server für die Sperrlisten: leer = automatisch (wie das System bzw. der Container), sonst eigene Adresse(n).
export function parseDnsServers (v) {
  return String(v || '').split(/[\s,;]+/).map(x => x.trim()).filter(Boolean).filter(x => {
    const m = x.match(/^\[?([0-9a-f:.]+?)\]?(?::(\d{1,5}))?$/i)
    if (!m) return false
    if (net.isIP(x)) return true
    return net.isIPv4(m[1]) || (net.isIPv6(m[1]) && x.startsWith('['))
  }).slice(0, 3)
}
const resolvers = new Map()
function resolverFor (servers) {
  const key = servers.join(',')
  if (!key) return { key: '', resolve4: (n) => dns.resolve4(n) }
  if (!resolvers.has(key)) {
    const r = new dns.Resolver({ timeout: 2500, tries: 1 })
    r.setServers(servers)
    resolvers.set(key, { key, resolve4: (n) => r.resolve4(n) })
  }
  return resolvers.get(key)
}
export function systemDnsServers () { return dns.getServers() }

async function lookup (name, res = resolverFor([])) {
  const ck = res.key + '|' + name
  if (cache.has(ck)) return cache.get(ck)
  let r = null
  try {
    const t = new Promise((resolve) => setTimeout(() => resolve('timeout'), 4000))
    const a = await Promise.race([res.resolve4(name), t])
    r = a === 'timeout' ? null : a
  } catch { r = [] }
  if (cache.size > 5000) cache.clear()
  if (r !== null) cache.set(ck, r)
  return r
}

// Rückgabe nur gültiger Treffer: 127.0.0.x – aber nicht die Fehlercodes 127.255.255.x (Abfrage über öffentliche DNS gesperrt) bzw. 127.0.1.255
const realHit = (ips) => Array.isArray(ips) && ips.some(ip => /^127\./.test(ip) && !/^127\.255\.255\./.test(ip) && ip !== '127.0.1.255' && ip !== '127.0.0.1')
const blocked = (ips) => Array.isArray(ips) && ips.some(ip => /^127\.255\.255\./.test(ip))

// Erste öffentliche IP aus den Received-Kopfzeilen (= einliefernder Server)
export function senderIp (headers) {
  const rec = headers && headers.get('received')
  const list = Array.isArray(rec) ? rec : rec ? [rec] : []
  for (const r of list.slice(0, 6)) {
    for (const m of String(r).matchAll(/\[(\d{1,3}(?:\.\d{1,3}){3})\]|\((?:[^()]*?\s)?(\d{1,3}(?:\.\d{1,3}){3})\)/g)) {
      const ip = m[1] || m[2]
      if (net.isIPv4(ip) && !/^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)/.test(ip)) return ip
    }
  }
  return null
}

export async function blocklistCheck ({ ip, domains }, cfg) {
  const out = { hits: [], warning: null }
  const ipLists = String(cfg.ipLists ?? DEFAULT_IP_LISTS).split(/\s+/).filter(Boolean).slice(0, 5)
  const dLists = String(cfg.domainLists ?? DEFAULT_DOMAIN_LISTS).split(/\s+/).filter(Boolean).slice(0, 5)
  const jobs = []
  if (ip && net.isIPv4(ip)) {
    const rev = ip.split('.').reverse().join('.')
    for (const l of ipLists) jobs.push({ name: `${rev}.${l}`, list: l, text: `Absender-Server ${ip} steht auf ${l}` })
  }
  const ds = [...new Set((domains || []).map(baseDomain).filter(d => d && d.includes('.')))].slice(0, 8)
  for (const d of ds) for (const l of dLists) jobs.push({ name: `${d}.${l}`, list: l, text: `Domain ${d} steht auf ${l}` })
  // alle Abfragen gleichzeitig, insgesamt höchstens ~5 Sekunden
  const res = resolverFor(parseDnsServers(cfg.dnsServer))
  const results = await Promise.all(jobs.map(j => lookup(j.name, res).then(r => ({ j, r }))))
  for (const { j, r } of results) {
    if (blocked(r)) out.warning = `${j.list} beantwortet keine Abfragen über diesen DNS-Server`
    else if (realHit(r) && !out.hits.includes(j.text)) out.hits.push(j.text)
  }
  return out
}

// Testabfrage: jede Liste hat einen offiziellen Testeintrag, der immer „gelistet“ meldet.
const TEST_IP = '2.0.0.127' // = 127.0.0.2
const TEST_DOMAIN = { 'dbl.spamhaus.org': 'dbltest.com', 'multi.surbl.org': 'surbl-org-permanent-test-point.com' }
export async function testBlocklists (cfg) {
  const servers = parseDnsServers(cfg.dnsServer)
  const res = resolverFor(servers)
  const ipLists = String(cfg.ipLists ?? DEFAULT_IP_LISTS).split(/\s+/).filter(Boolean).slice(0, 5)
  const dLists = String(cfg.domainLists ?? DEFAULT_DOMAIN_LISTS).split(/\s+/).filter(Boolean).slice(0, 5)
  const jobs = [
    ...ipLists.map(l => ({ list: l, name: `${TEST_IP}.${l}` })),
    ...dLists.map(l => ({ list: l, name: `${TEST_DOMAIN[l] || 'test'}.${l}`, unknown: !TEST_DOMAIN[l] }))
  ]
  const out = []
  for (const j of jobs) {
    let r = null
    try {
      const t = new Promise((resolve) => setTimeout(() => resolve('timeout'), 5000))
      r = await Promise.race([res.resolve4(j.name), t])
    } catch (e) { r = e && e.code === 'ENOTFOUND' ? [] : 'error' }
    let state
    if (r === 'timeout' || r === 'error') state = 'noanswer'
    else if (blocked(r)) state = 'blocked'
    else if (realHit(r)) state = 'ok'
    else state = j.unknown ? 'unknown' : 'nohit'
    out.push({ list: j.list, state })
  }
  return { servers: servers.length ? servers : dns.getServers(), auto: !servers.length, results: out }
}
