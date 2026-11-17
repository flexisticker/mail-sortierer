// Lernen aus Korrekturen: feste Absender-Regeln + Beispiele für die KI. Das Modell selbst wird nicht trainiert.
import { db, now, log } from './db.js'
import { getConfig, targetLabel } from './config.js'

// Freemail-Domains: hier sagt die Domain nichts über den Absender aus
export const FREEMAIL = new Set(('gmail.com googlemail.com gmx.de gmx.net gmx.at gmx.ch web.de t-online.de outlook.com outlook.de hotmail.com hotmail.de ' +
  'live.com live.de yahoo.com yahoo.de icloud.com me.com mac.com aol.com aol.de freenet.de mail.de posteo.de arcor.de online.de 1und1.de vodafone.de proton.me protonmail.com').split(' '))

export function addExample (mail, target, previous, origin) {
  db.prepare(`INSERT INTO examples (msgid, from_addr, domain, subject, snippet, target, previous, origin, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(mail.msgid || null, mail.from_addr || '', mail.domain || '', String(mail.subject || '').slice(0, 300),
    String(mail.snippet || '').slice(0, 500), target, previous || null, origin, now())
}

// Absender-Regel nachführen. Gleiche Korrektur mehrmals → Regel gilt fest; widersprüchliche Korrekturen → Regel aus (gemischter Absender)
export function learnSender (addr, target, origin) {
  if (!addr || !addr.includes('@')) return null
  const cfg = getConfig()
  const need = Math.max(1, Number(cfg.ruleAfter) || 2)
  const r = db.prepare("SELECT * FROM rules WHERE kind = 'sender' AND value = ?").get(addr)
  const t = now()
  if (!r) {
    const state = need <= 1 ? 'active' : 'suggest'
    db.prepare("INSERT INTO rules (kind, value, target, state, hits, conflicts, origin, created_at, updated_at) VALUES ('sender', ?, ?, ?, 1, 0, ?, ?, ?)")
      .run(addr, target, state, origin, t, t)
    return state
  }
  if (r.origin === 'hand') return r.state // von Hand angelegte Regeln nicht automatisch ändern
  if (r.target === target) {
    const hits = r.hits + 1
    const state = r.state === 'off' ? 'off' : (hits >= need ? 'active' : 'suggest')
    db.prepare('UPDATE rules SET hits = ?, state = ?, updated_at = ? WHERE id = ?').run(hits, state, t, r.id)
    return state
  }
  const conflicts = r.conflicts + 1
  // Zweiter Widerspruch → der Absender schickt Verschiedenes: keine feste Regel, die KI entscheidet mit Beispielen
  const state = conflicts >= 2 ? 'off' : (need <= 1 ? 'active' : 'suggest')
  db.prepare('UPDATE rules SET target = ?, hits = 1, conflicts = ?, state = ?, origin = ?, updated_at = ? WHERE id = ?')
    .run(target, conflicts, state, conflicts >= 2 ? 'gemischt' : origin, t, r.id)
  return state
}

// Absender als vertrauenswürdig merken (nach „ist harmlos“ bzw. aus „Achtung Verdacht“/„Spam“ herausgezogen)
export function trustSender (addr, origin) {
  if (!addr || !addr.includes('@')) return
  const t = now()
  db.prepare(`INSERT INTO rules (kind, value, target, state, hits, conflicts, origin, created_at, updated_at) VALUES ('trust', ?, 'inbox', 'active', 1, 0, ?, ?, ?)
    ON CONFLICT(kind, value) DO UPDATE SET state = 'active', hits = rules.hits + 1, updated_at = excluded.updated_at`).run(addr, origin, t, t)
}
export function isTrusted (mail) {
  if (db.prepare("SELECT 1 FROM rules WHERE kind = 'trust' AND value = ? AND state = 'active'").get(mail.from_addr || '')) return true
  return !!(mail.domain && !FREEMAIL.has(mail.domain) && db.prepare("SELECT 1 FROM rules WHERE kind = 'trustdomain' AND value = ? AND state = 'active'").get(mail.domain))
}
// Bekannt = Kontaktliste oder schon mehrfach unauffällig gesehen
export function isKnown (mail) {
  if (contactFor(mail.from_addr)) return true
  const n = db.prepare("SELECT COUNT(*) n FROM mails WHERE from_addr = ? AND decision NOT IN ('verdacht', 'spam') AND COALESCE(risk, 0) < 30").get(mail.from_addr || '').n
  return n >= 3
}

// Eine Korrektur verarbeiten (aus Outlook erkannt oder in der Oberfläche gewählt)
export function recordCorrection (mail, target, origin) {
  const previous = mail.decision || null
  if ((previous === 'verdacht' || previous === 'spam') && target !== previous) trustSender(mail.from_addr, origin)
  addExample(mail, target, previous, origin)
  const state = learnSender(mail.from_addr, target, origin)
  log('info', `Gelernt (${origin === 'outlook' ? 'aus Outlook' : 'in der Oberfläche'}): ${mail.from_addr || '?'} „${String(mail.subject || '').slice(0, 60)}“ → ${targetLabel(target)}` +
    (previous && previous !== target ? ` (vorher ${targetLabel(previous)})` : '') + (state === 'active' ? ' – Regel gilt jetzt fest' : state === 'off' ? ' – Absender gemischt, KI entscheidet mit Beispielen' : ''))
}

export function ruleFor (mail) {
  const s = db.prepare("SELECT * FROM rules WHERE kind = 'sender' AND value = ? AND state = 'active'").get(mail.from_addr || '')
  if (s) return s
  if (!mail.domain || FREEMAIL.has(mail.domain)) return null
  // Domain-Regel auch für Subdomains (rechnung.firma.de → firma.de)
  const parts = mail.domain.split('.')
  for (let i = 0; i < parts.length - 1; i++) {
    const d = parts.slice(i).join('.')
    const r = db.prepare("SELECT * FROM rules WHERE kind = 'domain' AND value = ? AND state = 'active'").get(d)
    if (r) return r
  }
  return null
}

const words = (s) => new Set(String(s || '').toLowerCase().replace(/[^a-zäöüß0-9 ]/g, ' ').split(/\s+/).filter(w => w.length > 3))

// Passende Beispiele für die KI: gleicher Absender, gleiche Domain, dann ähnlicher Betreff
export function examplesFor (mail, n) {
  const max = Math.max(0, Number(n) || 0)
  if (!max) return []
  const seen = new Set()
  const out = []
  const push = (rows) => {
    for (const r of rows) {
      if (out.length >= max) return
      const key = r.subject + '|' + r.from_addr
      if (seen.has(key) || (mail.msgid && r.msgid === mail.msgid)) continue
      seen.add(key); out.push(r)
    }
  }
  push(db.prepare('SELECT * FROM examples WHERE from_addr = ? ORDER BY id DESC LIMIT 4').all(mail.from_addr || ''))
  if (mail.domain && !FREEMAIL.has(mail.domain)) push(db.prepare('SELECT * FROM examples WHERE domain = ? ORDER BY id DESC LIMIT 3').all(mail.domain))
  if (out.length < max) {
    const w = words(mail.subject + ' ' + String(mail.snippet || '').slice(0, 200))
    if (w.size) {
      const scored = db.prepare('SELECT * FROM examples ORDER BY id DESC LIMIT 400').all()
        .map(r => { let s = 0; for (const x of words(r.subject + ' ' + String(r.snippet || '').slice(0, 200))) if (w.has(x)) s++; return { r, s } })
        .filter(x => x.s >= 2).sort((a, b) => b.s - a.s).map(x => x.r)
      push(scored)
    }
  }
  return out
}

export function contactFor (addr) {
  if (!addr) return null
  return db.prepare('SELECT * FROM contacts WHERE email = ?').get(addr)
}
