// Einstellungen mit Vorgaben. Gespeichert in kv 'config'; Passwort separat verschlüsselt (secrets.js).
import { kvGet, kvSet } from './db.js'
import { listAccounts } from './accounts.js'

// docker (Unraid/NAS) oder windows (Setup mit Dienst)
export const PLATFORM = process.env.APP_PLATFORM || (process.platform === 'win32' ? 'windows' : 'docker')

// Kategorien = Unterordner von „Sortiert“. id bleibt fest (Regeln/Beispiele zeigen darauf), Name/Beschreibung änderbar.
export const DEFAULT_CATEGORIES = [
  { id: 'kunden', name: 'Kunden', desc: 'Anfragen, Aufträge, Rückfragen, Freigaben und Reklamationen von Kunden (echte Personen oder Firmen, die bei uns bestellen oder bestellen wollen).' },
  { id: 'lieferanten', name: 'Lieferanten', desc: 'Mails von Lieferanten und Dienstleistern: Angebote, Bestell- und Auftragsbestätigungen, Lieferinfos, Rückfragen zu unseren Bestellungen.' },
  { id: 'rechnungen', name: 'Rechnungen und Zahlungen', desc: 'Rechnungen, Gutschriften, Mahnungen, Zahlungseingänge, Kontoauszüge, PayPal-/Bank-Zahlungsmeldungen, Abbuchungen und Abo-Rechnungen.' },
  { id: 'versand', name: 'Versand und Shop', desc: 'Sendungsverfolgung und Paketdienste (DHL, DPD, UPS, Sendcloud), Bestellbenachrichtigungen aus Shops und Marktplätzen (eBay, WooCommerce, Amazon) über Verkäufe.' },
  { id: 'system', name: 'System-Meldungen', desc: 'Automatische Meldungen von Software und Servern: NAS/Server, GitHub, Updates, Sicherungen, Anmelde- und Sicherheitshinweise, Konto-Bestätigungen, Passwort-Mails.' },
  { id: 'newsletter', name: 'Newsletter und Werbung', desc: 'Newsletter, Werbung, Angebote und Rabattaktionen, Umfragen, Social-Media-Benachrichtigungen, Webinar-Einladungen.' },
  { id: 'ausmisten', name: 'Ausmisten', desc: 'Offensichtlich unwichtige oder unerwünschte Mails: Spam, unseriöse Werbung, Kaltakquise, Gewinnspiele, Mails, die niemand braucht.' },
  // Sonderordner – die KI wählt sie nie selbst, nur die Sicherheitsprüfung (security.js)
  { id: 'spam', name: 'Spam', desc: 'Mails von Absendern auf Spam-Sperrlisten oder vom Mailserver als Spam markiert.', system: true },
  { id: 'verdacht', name: 'Achtung Verdacht', desc: 'Verdacht auf Phishing, Betrug oder gefährliche Anhänge. Nichts anklicken, nichts öffnen.', system: true }
]

export const DEFAULT_CONFIG = {
  imap: { host: '', port: 993, secure: true, user: '', allowSelfSigned: false }, // nur noch für den Umzug von 1.0
  invoices: {
    accountId: 0,            // Sammel-Postfach (z. B. rechnung@firma.de); 0 = Rechnungen nicht sammeln
    root: 'Rechnungen',      // Rechnungen/2026/2026-11
    privateName: 'Privat',   // Rechnungen/Privat/2026
    noInvoiceName: 'Keine Rechnung',
    orderName: 'Auftragsbestätigungen', // Rechnungen/Auftragsbestätigungen/2026
    flagOpen: true,          // offene Rechnungen in Outlook mit Fähnchen
    fromYear: 0,             // Rechnungen erst ab diesem Jahr zu Lexware prüfen (0 = alle); ältere = „Jahr abgeschlossen“
    scanEnabled: !!process.env.SCAN_DIR, // Windows-Setup: im Setup gewählter Scan-Ordner ist gleich eingeschaltet
    scanDir: process.env.SCAN_DIR || (PLATFORM === 'windows' ? '' : '/scan'), // Docker: Freigabe → /scan, Windows: Ordner wählen (z. B. C:\\Scans)
    scanUser: '',            // Windows: Benutzer für eine Netzwerkfreigabe (\\\\NAS\\scan), Passwort verschlüsselt
    lexwareUrl: 'https://api.lexware.io',
    ownerName: '',           // Name des Inhabers, wie er in Rechnungsanschriften steht
    companies: ''            // je Zeile eine Firma/Marke – steht sie in der Rechnung, ist sie geschäftlich
  },
  security: {
    phishThreshold: 60,      // ab dieser Punktzahl → Ordner „Achtung Verdacht“
    warnThreshold: 30,       // ab hier Warnhinweis in der Oberfläche
    blockDangerous: true,    // gefährliche Anhänge immer als Verdacht behandeln
    brands: '',              // zusätzliche Marken (je Zeile „Name = domain.de, domain2.de“), die oft gefälscht werden
    dnsbl: true,             // Spam-Sperrlisten abfragen (nur IP/Domain gehen an den Listenbetreiber, kein Inhalt)
    ipLists: 'zen.spamhaus.org\nbl.spamcop.net',
    domainLists: 'dbl.spamhaus.org\nmulti.surbl.org',
    dnsServer: '',           // DNS-Server für die Sperrlisten, leer = automatisch (wie das System)
    spamHeader: true         // Spam-Kennzeichnung des Mailservers (X-Spam-Flag) übernehmen
  },
  cleanup: { spam: 0, verdacht: 0, mode: 'trash' }, // Tage im Ordner, 0 = nie aufräumen
  business: { name: '', description: '' }, // Betrieb – nur als Hintergrund für die KI
  ollama: { url: PLATFORM === 'windows' ? 'http://localhost:11434' : '', model: 'qwen2.5:7b', timeoutSec: 120, numCtx: 4096 },
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
  // Kategorien: feste (IDs bleiben, Name/Beschreibung änderbar) + eigene Ordner (id c_…)
  const saved = Array.isArray(c.categories) ? c.categories : []
  const fixed = DEFAULT_CATEGORIES.map(d => {
    const s = saved.find(x => x.id === d.id) || {}
    return { id: d.id, name: cleanFolderName(s.name) || d.name, desc: String(s.desc || d.desc).slice(0, 600), off: d.system ? false : !!s.off, system: !!d.system }
  })
  const custom = saved.filter(x => x && /^c_[a-z0-9]{4,16}$/.test(x.id) && cleanFolderName(x.name))
    .map(x => ({ id: x.id, name: cleanFolderName(x.name), desc: String(x.desc || '').slice(0, 600), off: !!x.off, custom: true }))
  c.categories = [...fixed.filter(x => !x.system), ...custom, ...fixed.filter(x => x.system)]
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
// Ordner, zwischen denen die KI wählt (ohne „Achtung Verdacht“)
export const kiCategories = (c = getConfig()) => activeCategories(c).filter(x => !x.system)
export const companyList = (c = getConfig()) => String(c.invoices.companies || '').split(/\n|,/).map(x => x.trim()).filter(Boolean).slice(0, 20)
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
