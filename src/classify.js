// Einordnen einer Mail: eigene Adresse → Regel → bekannter Kunde → lokale KI.
import { kiCategories, categoryById, ownAddresses, targetLabel } from './config.js'
import { ruleFor, examplesFor, contactFor } from './learn.js'
import { chatJson } from './ollama.js'

function schema (ids) {
  return {
    type: 'object',
    properties: {
      kategorie: { type: 'string', enum: [...ids, 'posteingang'] },
      sicherheit: { type: 'integer', minimum: 0, maximum: 100 },
      grund: { type: 'string' },
      verdacht: { type: 'integer', minimum: 0, maximum: 100 }
    },
    required: ['kategorie', 'sicherheit', 'grund', 'verdacht']
  }
}

// „eines kleinen Betriebs (Firma – Beschreibung)“ aus den Einstellungen
export function bizText (cfg) {
  const b = cfg.business || {}
  const name = String(b.name || '').trim(); const desc = String(b.description || '').trim()
  return name || desc ? `des Betriebs ${[name, desc].filter(Boolean).join(' – ')}` : 'eines kleinen Betriebs'
}

function systemPrompt (cfg) {
  const cats = kiCategories(cfg)
  return [
    `Du sortierst E-Mails ${bizText(cfg)} in Ordner.`,
    'Wähle genau eine Kategorie:',
    ...cats.map(c => `- ${c.id}: ${c.name} – ${c.desc}`),
    '- posteingang: Persönliche oder wichtige Mails, die der Inhaber selbst lesen muss und die in keine Kategorie eindeutig passen, sowie alles, was unklar ist.',
    '',
    'Regeln:',
    '- Eine Mail von einem echten Kunden ist immer „kunden“, auch wenn sie eine Rechnung oder Zahlung erwähnt.',
    '- Rechnungen und Zahlungsbelege von Lieferanten, Dienstleistern oder Abos sind „rechnungen“.',
    '- Bei Zweifeln „posteingang“ wählen oder eine niedrige Sicherheit angeben. Lieber liegen lassen als falsch einsortieren.',
    '- „ausmisten“ nur für eindeutig wertlose Mails.',
    '- Beachte die Beispiele, wie der Nutzer ähnliche Mails selbst einsortiert hat – sie haben Vorrang.',
    '- sicherheit: 0–100, wie sicher du dir bist. grund: kurz auf Deutsch (höchstens 15 Wörter).',
    '- verdacht: 0–100, wie wahrscheinlich die Mail Phishing oder Betrug ist (gefälschter Absender, will Passwörter, TANs oder Zahlungen, droht mit Sperrung, gefälschte Rechnung). Normale Mails: 0–10.',
    'Antworte nur mit JSON.'
  ].join('\n')
}

function describe (mail, extra = []) {
  return [
    `Von: ${mail.from_name ? mail.from_name + ' ' : ''}<${mail.from_addr}>`,
    `Betreff: ${mail.subject || '(ohne Betreff)'}`,
    mail.hints ? `Hinweise: ${mail.hints}` : '',
    ...extra,
    'Text (Anfang):',
    String(mail.snippet || '(leer)').slice(0, 1500)
  ].filter(Boolean).join('\n')
}

export async function classify (mail, cfg) {
  const own = ownAddresses(cfg)
  if (mail.from_addr && own.includes(mail.from_addr)) {
    return { decision: 'inbox', source: 'own', confidence: 100, reason: 'eigene Adresse' }
  }
  const rule = ruleFor(mail)
  if (rule && (rule.target === 'inbox' || (categoryById(rule.target, cfg) && !categoryById(rule.target, cfg).off))) {
    return { decision: rule.target, source: 'rule', confidence: 100, reason: rule.kind === 'sender' ? 'Regel für diesen Absender' : `Regel für ${rule.value}` }
  }
  const contact = contactFor(mail.from_addr)
  const extra = []
  if (contact && contact.target === 'kunden' && !categoryById('kunden', cfg).off) {
    return { decision: 'kunden', source: 'contact', confidence: 100, reason: 'bekannter Kunde' + (contact.name ? ` (${contact.name})` : '') }
  }
  if (contact) extra.push(`Bekannter Kontakt: ${targetLabel(contact.target, cfg)}${contact.name ? ' – ' + contact.name : ''}`)

  const ids = kiCategories(cfg).map(c => c.id)
  const ex = examplesFor(mail, cfg.maxExamples)
  const messages = [{ role: 'system', content: systemPrompt(cfg) }]
  for (const e of ex) {
    messages.push({ role: 'user', content: describe(e) })
    messages.push({ role: 'assistant', content: JSON.stringify({ kategorie: e.target === 'inbox' ? 'posteingang' : e.target, sicherheit: 100, grund: 'So hat der Nutzer es selbst einsortiert.', verdacht: 0 }) })
  }
  messages.push({ role: 'user', content: describe(mail, extra) })

  const r = await chatJson(cfg, messages, schema(ids))
  let cat = String(r.kategorie || '').toLowerCase()
  if (cat === 'posteingang') cat = 'inbox'
  if (cat !== 'inbox' && !ids.includes(cat)) cat = 'inbox'
  const conf = Math.max(0, Math.min(100, Math.round(Number(r.sicherheit) || 0)))
  const reason = String(r.grund || '').replace(/\s+/g, ' ').slice(0, 200)
  const suspicion = Math.max(0, Math.min(100, Math.round(Number(r.verdacht) || 0)))
  const need = cat === 'ausmisten' ? Number(cfg.minConfidenceTrash) || 85 : Number(cfg.minConfidence) || 70
  if (cat !== 'inbox' && conf < need) {
    return { decision: 'inbox', source: 'ki', confidence: conf, reason: `unsicher – Vorschlag „${targetLabel(cat, cfg)}“: ${reason}`, suggestion: cat, suspicion }
  }
  return { decision: cat, source: 'ki', confidence: conf, reason, examples: ex.length, suspicion }
}
