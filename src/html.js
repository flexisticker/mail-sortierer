// Kleine HTML-Helfer für die serverseitig erzeugten Seiten (alles maskiert).
export const esc = (s) => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]))

export const VERSION = process.env.APP_VERSION || '1.8.0'

const NAV = [
  ['/', 'Übersicht'],
  ['/mails', 'Mails'],
  ['/rechnungen', 'Rechnungen'],
  ['/gelernt', 'Gelernt'],
  ['/protokoll', 'Protokoll'],
  ['/einstellungen', 'Einstellungen']
]

export function page ({ title, body, session, path = '/', msg, err, wide }) {
  const nav = session
    ? `<nav class="nav">${NAV.map(([href, label]) => `<a href="${href}"${(href === '/' ? path === '/' : path.startsWith(href)) ? ' class="on"' : ''}>${label}</a>`).join('')}
      <form method="post" action="/abmelden" class="logout">${csrf(session)}<button class="link">Abmelden</button></form></nav>`
    : ''
  return `<!doctype html>
<html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)} · Mail-Sortierer</title>
<link rel="stylesheet" href="/app.css"><link rel="icon" href="/icon.svg" type="image/svg+xml">
<script src="/app.js" defer></script></head>
<body><header class="top"><a class="brand" href="/"><img src="/icon.svg" alt="" width="28" height="28"><span>Mail-Sortierer</span></a>${nav}</header>
<main class="${wide ? 'main wide' : 'main'}">
${msg ? `<div class="alert ok">${esc(msg)}</div>` : ''}${err ? `<div class="alert bad">${esc(err)}</div>` : ''}
${body}
</main>
<footer class="foot">Mail-Sortierer ${esc(VERSION)} · lokale KI, nichts verlässt dein Netz</footer>
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
