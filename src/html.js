// Kleine HTML-Helfer für die serverseitig erzeugten Seiten (alles maskiert).
export const esc = (s) => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]))

export const VERSION = process.env.APP_VERSION || '2.8.0'

// Oben nur: Mail · Rechnungen · Verwaltung. Alles Übrige steckt in der Verwaltung (zweite Zeile).
const MANAGE_PATHS = ['/uebersicht', '/mails', '/gelernt', '/protokoll']
const ADMIN_PATHS = ['/einstellungen', '/signaturen', '/verwaltung']
const inArea = (path, list) => list.some(p => path === p || path.startsWith(p + '/') || path.startsWith(p + '?'))
export const manageHome = (session) => session.features && session.features.manage ? '/uebersicht' : '/einstellungen'

function navItems (session) {
  const f = session.features || {}
  return [
    ...(f.webmail ? [['/post', '✉ Mail', (p) => inArea(p, ['/post'])]] : []),
    ...(session.showInvoices ? [['/rechnungen', '€ Rechnungen', (p) => inArea(p, ['/rechnungen'])]] : []),
    [manageHome(session), '⚙ Verwaltung', (p) => inArea(p, [...MANAGE_PATHS, ...ADMIN_PATHS])]
  ]
}
function subNav (session, path) {
  if (!inArea(path, [...MANAGE_PATHS, ...ADMIN_PATHS])) return ''
  const f = session.features || {}
  const items = [
    ...(f.manage ? [['/uebersicht', 'Übersicht'], ['/mails', 'Sortierung'], ['/gelernt', 'Gelernt'], ['/protokoll', 'Protokoll']] : []),
    ['/einstellungen', 'Einstellungen'],
    ...(f.webmail ? [['/signaturen', 'Signaturen']] : []),
    ...(session.admin ? [['/verwaltung', 'System']] : [])
  ]
  return `<nav class="subnav" aria-label="Verwaltung">${items.map(([h, l]) => `<a href="${h}"${inArea(path, [h]) ? ' class="on" aria-current="page"' : ''}>${l}</a>`).join('')}</nav>`
}

export function page ({ title, body, session, path = '/', msg, err, wide, full }) {
  const ok = session && session.stage === 'full' && session.features
  const nav = ok
    ? `<nav class="nav">${navItems(session).map(([href, label, on]) => `<a href="${href}"${on(path) ? ' class="on"' : ''}>${label}</a>`).join('')}
      <form method="post" action="/abmelden" class="logout">${csrf(session)}<button class="link" title="${esc(session.display || session.name)} abmelden">Abmelden</button></form></nav>`
    : ''
  return `<!doctype html>
<html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)} · Postwart</title>
<link rel="stylesheet" href="/app.css"><link rel="icon" href="/icon.svg" type="image/svg+xml">
<script src="/app.js" defer></script></head>
<body${full ? ' class="app"' : ''}><header class="top"><a class="brand" href="/"><img src="/icon.svg" alt="" width="28" height="28"><span>Postwart</span></a>${nav}
<button type="button" class="theme-btn" data-theme-toggle title="Darstellung: automatisch / hell / dunkel" aria-label="Hell oder dunkel umschalten"><span class="ti-auto" title="automatisch"><svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 3v18a9 9 0 0 0 0-18z" fill="currentColor"/></svg></span><span class="ti-light"><svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg></span><span class="ti-dark"><svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg></span></button></header>
${ok ? subNav(session, path) : ''}
<main class="${full ? 'main full' : wide ? 'main wide' : 'main'}">
${msg ? `<div class="alert ok">${esc(msg)}</div>` : ''}${err ? `<div class="alert bad">${esc(err)}</div>` : ''}
${body}
</main>
${full ? '' : `<footer class="foot">Postwart ${esc(VERSION)} · sortiert, schützt und räumt auf – mit lokaler KI, nichts verlässt dein Netz</footer>`}
</body></html>`
}

export const csrf = (session) => session ? `<input type="hidden" name="csrf" value="${esc(session.csrf)}">` : ''

export function fmtDate (iso) {
  if (!iso) return ''
  const d = new Date(iso)
  if (isNaN(d)) return ''
  const p = (n) => String(n).padStart(2, '0')
  return `${p(d.getDate())}.${p(d.getMonth() + 1)}.${String(d.getFullYear()).slice(2)} ${p(d.getHours())}:${p(d.getMinutes())}`
}

export function options (list, selected) {
  return list.map(([v, l]) => `<option value="${esc(v)}"${String(v) === String(selected) ? ' selected' : ''}>${esc(l)}</option>`).join('')
}

export const STATUS_LABEL = {
  planned: 'Vorgemerkt',
  moved: 'Verschoben',
  kept: 'Bleibt im Posteingang',
  undone: 'Rückgängig',
  error: 'Fehler',
  gone: 'Nicht mehr da',
  deleted: 'Aufgeräumt'
}

export const SOURCE_LABEL = {
  rule: 'Regel',
  contact: 'Kontaktliste',
  ki: 'KI',
  own: 'eigene Adresse',
  correction: 'Korrektur',
  manual: 'von Hand',
  security: 'Sicherheitsprüfung'
}
