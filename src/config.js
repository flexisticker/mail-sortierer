// Einstellungen mit Vorgaben. Gespeichert in kv 'config'; Passwort separat verschlüsselt (secrets.js).
import { kvGet, kvSet } from './db.js'
import { listAccounts } from './accounts.js'

// Kategorien = Unterordner von „Sortiert“. id bleibt fest (Regeln/Beispiele zeigen darauf), Name/Beschreibung änderbar.
export const DEFAULT_CATEGORIES = [
  { id: 'kunden', name: 'Kunden', desc: 'Anfragen, Aufträge, Rückfragen, Freigaben und Reklamationen von Kunden (echte Personen oder Firmen, die bei uns bestellen oder bestellen wollen).' },
  { id: 'lieferanten', name: 'Lieferanten', desc: 'Mails von Lieferanten und Dienstleistern: Angebote, Bestell- und Auftragsbestätigungen, Lieferinfos, Rückfragen zu unseren Bestellungen.' },
  { id: 'rechnungen', name: 'Rechnungen und Zahlungen', desc: 'Rechnungen, Gutschriften, Mahnungen, Zahlungseingänge, Kontoauszüge, PayPal-/Bank-Zahlungsmeldungen, Abbuchungen und Abo-Rechnungen.' },
  { id: 'versand', name: 'Versand und Shop', desc: 'Sendungsverfolgung und Paketdienste (DHL, DPD, UPS, Sendcloud), Bestellbenachrichtigungen aus Shops und Marktplätzen (eBay, WooCommerce, Amazon) über Verkäufe.' },
  { id: 'system', name: 'System-Meldungen', desc: 'Automatische Meldungen von Software und Servern: Unraid, GitHub, Updates, Sicherungen, Anmelde- und Sicherheitshinweise, Konto-Bestätigungen, Passwort-Mails.' },
  { id: 'newsletter', name: 'Newsletter und Werbung', desc: 'Newsletter, Werbung, Angebote und Rabattaktionen, Umfragen, Social-Media-Benachrichtigungen, Webinar-Einladungen.' },
  { id: 'ausmisten', name: 'Ausmisten', desc: 'Offensichtlich unwichtige oder unerwünschte Mails: Spam, unseriöse Werbung, Kaltakquise, Gewinnspiele, Mails, die niemand braucht.' }
]

export const DEFAULT_CONFIG = {
  imap: { host: '', port: 993, secure: true, user: '', allowSelfSigned: false }, // nur noch für den Umzug von 1.0
  invoices: {
    accountId: 0,            // Sammel-Postfach (z. B. rechnung@flexisticker.de); 0 = Rechnungen nicht sammeln
    root: 'Rechnungen',      // Rechnungen/2026/2026-11
    privateName: 'Privat',   // Rechnungen/Privat/2026
    noInvoiceName: 'Keine Rechnung',
    flagOpen: true,          // offene Rechnungen in Outlook mit Fähnchen
    scanEnabled: false,
    scanDir: '/scan',        // Scanner-Ordner im Container (Unraid: Freigabe → /scan)
    lexwareUrl: 'https://api.lexware.io'
  },
  ollama: { url: 'http://192.168.1.10:11434', model: 'qwen2.5:7b', timeoutSec: 120, numCtx: 4096 },
  root: 'Sortiert',
  categories: DEFAULT_CATEGORIES,
  paused: false,
  intervalMin: 5,           // wie oft nachsehen
  batchDay: 25,             // Mails je Durchlauf tagsüber
  batchNight: 300,          // Mails je Durchlauf nachts (Altbestand)
  nightFrom: 22, nightTo: 6,
  backlog: true,            // Altbestand im Posteingang mitbearbeiten
  backlogMonths: 0,         // 0 = alle, sonst nur Mails der letzten n Monate
  minConfidence: 70,        // darunter bleibt die Mail im Posteingang
  minConfidenceTrash: 85,   // für „Ausmisten“ höhere Sicherheit nötig
  ruleAfter: 2,             // nach so vielen gleichen Korrekturen gilt eine Absender-Regel fest
  maxExamples: 6,           // Beispiele, die die KI je Mail mitbekommt
  ownAddresses: ''          // eigene Adressen (Komma) – Mails davon bleiben im Posteingang
}

function merge (base, over) {
  const out = { ...base }
  for (const [k, v] of Object.entries(over || {})) {
    if (v && typeof v === 'object' && !Array.isArray(v) && base[k] && typeof base[k] === 'object' && !Array.isArray(base[k])) out[k] = merge(base[k], v)
    else if (v !== undefined) out[k] = v
  }
  return out
}

export function getConfig () {
  const c = merge(DEFAULT_CONFIG, kvGet('config', {}))
  // Kategorien: gespeicherte Namen übernehmen, feste IDs behalten
  const saved = Array.isArray(c.categories) ? c.categories : []
  c.categories = DEFAULT_CATEGORIES.map(d => {
    const s = saved.find(x => x.id === d.id) || {}
    return { id: d.id, name: cleanFolderName(s.name) || d.name, desc: String(s.desc || d.desc).slice(0, 600), off: !!s.off }
  })
  return c
}

export function saveConfig (patch) {
  const c = merge(getConfig(), patch)
  kvSet('config', c)
  return getConfig()
}

// Ordnernamen ohne Zeichen, die in IMAP/Outlook Ärger machen
export function cleanFolderName (s) {
  return String(s || '').replace(/[/\\.&%*"<>|:?\x00-\x1f]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 60)
}

export const activeCategories = (c = getConfig()) => c.categories.filter(x => !x.off)
export const categoryById = (id, c = getConfig()) => c.categories.find(x => x.id === id)
export function targetLabel (id, c = getConfig()) {
  if (id === 'inbox') return 'Posteingang'
  const cat = categoryById(id, c)
  return cat ? cat.name : id
}

export function ownAddresses (c = getConfig()) {
  return String(c.ownAddresses || '').split(/[,;\s]+/).map(s => s.trim().toLowerCase()).filter(Boolean)
    .concat(listAccounts().map(a => String(a.user || '').toLowerCase()).filter(u => u.includes('@')))
}

export function isNight (c = getConfig(), d = new Date()) {
  const h = d.getHours()
  return c.nightFrom > c.nightTo ? (h >= c.nightFrom || h < c.nightTo) : (h >= c.nightFrom && h < c.nightTo)
}
