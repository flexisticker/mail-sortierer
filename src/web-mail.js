// Webmail-Seiten: Ordner + Liste, Mail lesen (bereinigt, abgeschottet), Anhänge, Aktionen.
import { page, esc, csrf, options } from './html.js'
import { listAccounts, getAccount, accountLabel } from './accounts.js'
import { getConfig, categoryById } from './config.js'
import { categoryPath, pathString, ensurePath } from './imap.js'
import { trustSender } from './learn.js'
import { log } from './db.js'
import {
  withMail, listFolders, listMessages, readMessage, attachmentsOf, assessForView, cleanMailHtml, textToHtml,
  imagesAllowed, allowImages, setFlags, moveMessages, deleteMessages, forgetCached
} from './webmail.js'
import { back, int, errText, flash } from './webutil.js'

const PER = 50
const isDrafts = (req) => { const f = req.folders.find(x => x.path === req.folder); return !!f && (f.special === '\\Drafts' || /^(drafts|entwürfe|entwurf)$/i.test(f.name)) }
const fmtShort = (iso) => {
  if (!iso) return ''
  const d = new Date(iso); const n = new Date()
  const p = (x) => String(x).padStart(2, '0')
  return d.toDateString() === n.toDateString() ? `${p(d.getHours())}:${p(d.getMinutes())}` : `${p(d.getDate())}.${p(d.getMonth() + 1)}.${String(d.getFullYear()).slice(2)}`
}
const fmtLong = (d) => d ? new Date(d).toLocaleString('de-DE', { timeZone: 'Europe/Berlin', dateStyle: 'full', timeStyle: 'short' }) : ''
const kb = (n) => n > 1048576 ? (n / 1048576).toFixed(1).replace('.', ',') + ' MB' : Math.max(1, Math.round(n / 1024)) + ' KB'
const who = (a) => a && (a.name || a.address) ? (a.name || a.address) : '(unbekannt)'
const addrList = (v) => (v && v.value ? v.value : []).map(x => x.name ? `${x.name} <${x.address}>` : x.address).join(', ')
const q = (o) => new URLSearchParams(Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined && v !== '' && v !== null))).toString()

// Ordnerpfade kurz merken (Prüfung, ob ein Ordner existiert)
const folderCache = new Map()
async function folders (req, acc, fresh = false) {
  const k = `${req.session.userId}:${acc.id}`
  const c = folderCache.get(k)
  if (!fresh && c && Date.now() - c.at < 60000) return c.list
  const list = await listFolders(acc)
  folderCache.set(k, { at: Date.now(), list })
  return list
}

export function registerMail (app) {
  // Postfach des Nutzers laden (gehört immer dem angemeldeten Nutzer – andere Datenbanken sind gar nicht erreichbar)
  const withAcc = async (req, res, next) => {
    const acc = getAccount(int(req.params.acc, 1, 1e9, 0))
    if (!acc) return res.status(404).send(page({ title: 'Nicht gefunden', body: '<h1>Postfach nicht gefunden</h1><p><a href="/post">Zum Postfach</a></p>', session: req.session }))
    req.acc = acc
    const folder = String(req.query.ordner || req.body?.ordner || 'INBOX')
    try {
      const list = await folders(req, acc, req.method === 'GET' && req.path.endsWith('/' + acc.id) && !req.get('X-Postwart-Teil'))
      if (!list.some(f => f.path === folder)) return back(res, `/post/${acc.id}`, { err: `Ordner „${folder}“ gibt es nicht.` })
      req.folders = list
      req.folder = folder
    } catch (e) {
      return res.status(502).send(page({ title: 'Postfach', session: req.session, path: '/post', body: `<h1>${esc(accountLabel(acc))}</h1><div class="alert bad">Verbindung zum Postfach fehlgeschlagen: ${esc(e.authenticationFailed ? 'Benutzer oder Passwort falsch.' : errText(e))}</div><p><a href="/einstellungen#postfaecher">Postfach prüfen</a></p>` }))
    }
    next()
  }

  app.get('/post', (req, res) => {
    const a = listAccounts()[0]
    if (!a) return res.send(page({ title: 'Mail', session: req.session, path: '/post', body: `<section class="card narrow wide-narrow"><h1>Willkommen bei Postwart</h1><p>Trag zuerst dein Postfach ein (Zugangsdaten wie in Outlook oder am Handy). Danach siehst du hier deine Mails.</p><a class="btn primary" href="/einstellungen#postfaecher">Postfach eintragen</a></section>` }))
    res.redirect(`/post/${a.id}`)
  })

  // Linke Spalte: alle Postfächer, beim offenen die Ordner
  const sidebar = (req) => {
    const accs = listAccounts()
    const folderList = `<ul>${req.folders.map(f => `<li class="d${Math.min(f.depth, 4)}"><a href="/post/${req.acc.id}?${q({ ordner: f.path })}"${f.path === req.folder ? ' class="on"' : ''}><span>${esc(f.name)}</span>${f.unseen ? `<b class="cnt">${f.unseen}</b>` : ''}</a></li>`).join('')}</ul>`
    return `<aside class="mail-side"><a class="btn primary block" href="/post/neu?postfach=${req.acc.id}">✎ Neue Mail</a>
      <details class="mail-folders" open><summary>${esc(accs.length > 1 ? 'Postfächer' : accountLabel(req.acc))} <span class="muted small">· ${esc(accs.length > 1 ? accountLabel(req.acc) + ' · ' : '')}${esc(((req.folders.find(f => f.path === req.folder) || {}).name) || req.folder)}</span></summary>
      ${accs.length > 1
        ? accs.map(a => a.id === req.acc.id
          ? `<div class="acc-block on"><div class="acc-name">${esc(accountLabel(a))}</div>${folderList}</div>`
          : `<div class="acc-block"><a class="acc-name" href="/post/${a.id}">${esc(accountLabel(a))}</a></div>`).join('')
        : folderList}
      <p class="side-links small"><a href="/signaturen">Signaturen</a> · <a href="/einstellungen#postfaecher">Postfächer</a></p>
    </details></aside>`
  }
  app.get('/post/go', (req, res) => res.redirect(`/post/${int(req.query.postfach, 1, 1e9, 0)}`))

  const moveTargets = (req) => req.folders.filter(f => f.path !== req.folder).map(f => [f.path, '  '.repeat(f.depth) + f.name])
  const listQuery = (req) => ({ ordner: req.folder, q: String(req.query.q || '').trim().slice(0, 100), seite: int(req.query.seite, 1, 100000, 1) > 1 ? int(req.query.seite, 1, 100000, 1) : '' })
  const listHref = (req, extra = {}) => `/post/${req.acc.id}?${q({ ...listQuery(req), ...extra })}`

  // Rechte Spalte: eine Mail (auch einzeln abrufbar, damit der Browser sie ohne Neuladen der Seite einsetzt)
  async function readPane (req, uid, nextUid) {
    const s = req.session
    const listUrl = listHref(req)
    const here = listHref(req, { uid })
    let msg
    try { msg = await readMessage(req.acc, req.folder, uid) } catch (e) { return { title: 'Mail', html: `<div class="alert bad">${esc(errText(e))}</div>` } }
    if (!msg) return { title: 'Mail', html: '<div class="alert bad">Die Mail gibt es nicht mehr.</div>' }
    const p = msg.parsed
    const from = (p.from && p.from.value && p.from.value[0]) || { name: '', address: '' }
    from.address = String(from.address || '').toLowerCase()
    const atts = attachmentsOf(p)
    const files = atts.filter(a => !(a.related && a.cid))
    const risk = assessForView(p, from)
    const flagged = msg.flags.includes('\\Flagged')
    const phishFlag = msg.flags.includes('$Phishing')
    const images = req.query.bilder === '1' || imagesAllowed(from.address)
    const cleaned = p.html ? cleanMailHtml(p.html, atts) : null
    const weiter = nextUid ? listHref(req, { uid: nextUid }) : ''
    const hidden = `${csrf(s)}<input type="hidden" name="ordner" value="${esc(req.folder)}"><input type="hidden" name="uids" value="${uid}"><input type="hidden" name="zurueck" value="${esc(here)}"><input type="hidden" name="liste" value="${esc(listUrl)}"><input type="hidden" name="weiter" value="${esc(weiter)}">`
    const act = (aktion, label, cls = 'btn sm', confirm = '', title = '') => `<button class="${cls}" name="aktion" value="${aktion}"${confirm ? ` data-confirm="${esc(confirm)}"` : ''}${title ? ` title="${esc(title)}"` : ''}>${label}</button>`
    const reply = (art) => `/post/neu?${q({ postfach: req.acc.id, ordner: req.folder, uid, art })}`
    const html = `<div class="read-tools">
        <a class="btn sm only-narrow" href="${esc(listUrl)}">‹ Zurück</a>
        ${isDrafts(req) ? `<a class="btn sm primary" href="${esc(reply('entwurf'))}">Entwurf bearbeiten</a>` : `<a class="btn sm primary" href="${esc(reply('antwort'))}">↩ Antworten</a>
        <a class="btn sm" href="${esc(reply('alle'))}">Allen antworten</a>
        <a class="btn sm" href="${esc(reply('weiter'))}">Weiterleiten ›</a>`}
        <form method="post" action="/post/${req.acc.id}/aktion" class="inline wrap pane-act">${hidden}
          ${act(flagged ? 'entmarkieren' : 'markieren', flagged ? '⚑ weg' : '⚑', 'btn sm', '', flagged ? 'Fähnchen entfernen' : 'Fähnchen setzen')}
          ${act('ungelesen', 'Ungelesen')}
          <select name="ziel" aria-label="Verschieben nach" class="sm-sel"><option value="">Verschieben …</option>${options(moveTargets(req), '')}</select>${act('verschieben', 'OK', 'btn sm', '', 'In den gewählten Ordner verschieben')}
          ${act('spam', 'Spam')}
          ${act('loeschen', '🗑 Löschen', 'btn sm ghost', '', 'In den Papierkorb')}
        </form>
      </div>
      ${risk.level === 'bad' || phishFlag ? `<div class="alert bad"><b>⚠ Vorsicht – diese Mail ist verdächtig.</b> Keine Links anklicken, keine Anhänge öffnen, keine Daten eingeben.<ul>${risk.reasons.slice(0, 6).map(r => `<li>${esc(r)}</li>`).join('')}</ul>
        <form method="post" action="/post/${req.acc.id}/aktion" class="inline">${hidden}<input type="hidden" name="absender" value="${esc(from.address)}">
          <button class="btn sm" name="aktion" value="harmlos" data-confirm="Absender ${esc(from.address)} als vertrauenswürdig merken und die Warnung entfernen?">Ist harmlos</button></form></div>`
        : risk.level === 'warn' ? `<div class="alert warn"><b>Auffällig:</b> ${risk.reasons.slice(0, 3).map(esc).join('; ')}</div>` : ''}
      <article class="mail-view">
        <h1 class="msubject">${esc(p.subject || '(ohne Betreff)')}</h1>
        <dl class="mhead"><dt>Von</dt><dd><b>${esc(from.name || from.address)}</b> <span class="muted">&lt;${esc(from.address)}&gt;</span></dd>
          <dt>An</dt><dd>${esc(addrList(p.to))}</dd>${p.cc ? `<dt>Kopie</dt><dd>${esc(addrList(p.cc))}</dd>` : ''}
          <dt>Datum</dt><dd>${esc(fmtLong(p.date))}</dd></dl>
        ${files.length ? `<ul class="atts">${files.map(a => `<li class="${a.danger ? 'att-bad' : a.warn ? 'att-warn' : ''}">📎 ${a.danger
          ? `<span>${esc(a.filename)}</span> <span class="small">(${kb(a.size)}) – gesperrt: ${esc(a.danger)}</span>`
          : `<a href="/post/${req.acc.id}/anhang?${q({ ordner: req.folder, uid, teil: a.i })}">${esc(a.filename)}</a> <span class="muted small">${kb(a.size)}</span>${/^(application\/pdf|image\/(png|jpe?g|gif|webp))$/i.test(a.contentType) ? ` · <a href="/post/${req.acc.id}/anhang?${q({ ordner: req.folder, uid, teil: a.i, ansehen: 1 })}" target="_blank" rel="noopener">ansehen</a>` : ''}${a.warn ? ` <span class="small warn-text">${esc(a.warn)}</span>` : ''}`}</li>`).join('')}</ul>` : ''}
        ${cleaned && cleaned.remoteImages && !images ? `<div class="imgbar">Externe Bilder (${cleaned.remoteImages}) blockiert – sie verraten dem Absender, dass und wann du die Mail liest.
          <a class="btn sm" href="${esc(listHref(req, { uid, bilder: 1 }))}">Bilder laden</a>
          <form method="post" action="/post/${req.acc.id}/bilder" class="inline">${csrf(s)}<input type="hidden" name="absender" value="${esc(from.address)}"><input type="hidden" name="zurueck" value="${esc(here)}"><button class="btn sm ghost">Immer bei ${esc(from.address)}</button></form></div>` : ''}
        <iframe class="mbody" title="Inhalt der Mail" sandbox="allow-popups allow-popups-to-escape-sandbox" referrerpolicy="no-referrer" src="/post/${req.acc.id}/inhalt?${q({ ordner: req.folder, uid, bilder: images ? 1 : '' })}"></iframe>
        <p class="muted small"><a href="/post/${req.acc.id}/anhang?${q({ ordner: req.folder, uid, teil: 'quelle' })}">Original herunterladen (.eml)</a></p>
      </article>`
    return { title: p.subject || 'Mail', html }
  }

  // --- Mail-Programm: Ordner | Liste | Mail ---
  app.get('/post/:acc', withAcc, async (req, res) => {
    const s = req.session
    const { q: query, seite: seiteQ } = listQuery(req)
    const seite = seiteQ || 1
    const uid = int(req.query.uid, 1, 2 ** 32, 0)
    // nur die Mail (der Browser setzt sie rechts ein, ohne die Seite neu zu laden)
    if (uid && req.get('X-Postwart-Teil') === 'lesen') {
      const r = await readPane(req, uid, 0)
      res.set('Cache-Control', 'no-store')
      return res.type('html').send(`<template data-title="${esc(r.title)}">${r.html}</template>`)
    }
    let data
    try { data = await listMessages(req.acc, req.folder, { page: seite, per: PER, q: query }) } catch (e) { return back(res, `/post/${req.acc.id}`, { err: errText(e) }) }
    const fname = (req.folders.find(f => f.path === req.folder) || {}).name || req.folder
    const pages = Math.max(1, Math.ceil(data.total / PER))
    const link = (p) => listHref(req, { seite: p > 1 ? p : '' })
    const sentLike = /gesendet|sent|entw|draft/i.test(fname)
    const idx = uid ? data.items.findIndex(m => m.uid === uid) : -1
    const nextUid = idx >= 0 ? (data.items[idx + 1] || data.items[idx - 1] || {}).uid : 0
    const pane = uid ? await readPane(req, uid, nextUid) : null
    const body = `<div class="mail-layout${pane ? ' has-read' : ''}">${sidebar(req)}
    <section class="mail-list"${query || pane ? '' : ' data-refresh="120"'}>
      <div class="mail-head"><h1>${esc(fname)} <span class="muted small">${data.total}</span></h1><a class="btn sm primary only-narrow" href="/post/neu?postfach=${req.acc.id}">✎ Neu</a>
        <form method="get" action="/post/${req.acc.id}" class="search"><input type="hidden" name="ordner" value="${esc(req.folder)}"><input name="q" value="${esc(query)}" placeholder="Suchen …" maxlength="100" aria-label="Suchen (Absender, Betreff, Text)"><button class="btn sm">🔍</button>${query ? `<a class="btn sm ghost" href="${esc(listHref(req, { q: '', seite: '' }))}" title="Suche beenden">✕</a>` : ''}</form></div>
      <form method="post" action="/post/${req.acc.id}/aktion" id="mbulk">${csrf(s)}<input type="hidden" name="ordner" value="${esc(req.folder)}"><input type="hidden" name="zurueck" value="${esc(link(seite))}">
      <div class="mail-tools">
        <label class="check" title="Alle wählen"><input type="checkbox" data-all="msel" aria-label="Alle wählen"></label>
        <button class="btn sm" name="aktion" value="gelesen">Gelesen</button>
        <button class="btn sm ghost" name="aktion" value="loeschen" data-confirm="Ausgewählte Mails löschen (in den Papierkorb)?">🗑</button>
        <details class="more"><summary class="btn sm">Mehr</summary><div class="more-box">
          <button class="btn sm" name="aktion" value="ungelesen">Ungelesen</button>
          <button class="btn sm" name="aktion" value="markieren">⚑ Fähnchen</button>
          <button class="btn sm" name="aktion" value="spam">Spam</button>
          <select name="ziel" aria-label="Verschieben nach"><option value="">Verschieben nach …</option>${options(moveTargets(req), '')}</select><button class="btn sm" name="aktion" value="verschieben">Verschieben</button>
        </div></details>
      </div>
      <ul class="mlist">${data.items.map(m => `<li class="${m.seen ? '' : 'unread'}${m.danger ? ' danger' : ''}${m.uid === uid ? ' sel' : ''}">
        <input type="checkbox" name="uids" value="${m.uid}" class="msel" aria-label="Auswählen">
        <a href="${esc(listHref(req, { uid: m.uid }))}" data-read>
          <span class="mfrom">${m.danger ? '<span class="dmark" title="Verdächtig – Vorsicht">!</span>' : ''}${esc(sentLike ? 'An: ' + who(m.to) : who(m.from))}</span>
          <span class="mmeta">${m.flagged ? '<span class="flag" title="Fähnchen">⚑</span> ' : ''}${m.att ? '📎 ' : ''}${fmtShort(m.date)}</span>
          <span class="msubj">${m.answered ? '<span title="beantwortet">↩</span> ' : ''}${esc(m.subject || '(ohne Betreff)')}</span></a></li>`).join('') || `<li class="muted empty">${query ? 'Nichts gefunden.' : 'Keine Mails in diesem Ordner.'}</li>`}</ul>
      </form>
      ${pages > 1 ? `<div class="pager">${seite > 1 ? `<a class="btn sm" href="${esc(link(seite - 1))}">‹ neuere</a>` : ''} <span class="muted small">Seite ${seite} von ${pages}</span> ${seite < pages ? `<a class="btn sm" href="${esc(link(seite + 1))}">ältere ›</a>` : ''}</div>` : ''}
    </section>
    <section class="mail-read"${pane ? ` data-uid="${uid}"` : ''}>${pane ? pane.html : '<div class="read-empty muted">Wähle links eine Mail aus.</div>'}</section>
    </div>`
    res.send(page({ title: pane ? pane.title : fname, body, session: s, path: '/post', full: true, ...flash(req) }))
  })

  // alte Adresse (Lesezeichen, Links aus 2.0/2.1)
  app.get('/post/:acc/lesen', (req, res) => res.redirect(`/post/${int(req.params.acc, 1, 1e9, 0)}?${q({ ordner: String(req.query.ordner || 'INBOX'), uid: int(req.query.uid, 1, 2 ** 32, 0) || '', bilder: req.query.bilder === '1' ? 1 : '' })}`))

  // Inhalt im abgeschotteten Rahmen: keine Skripte, eigene CSP (externe Bilder nur, wenn erlaubt)
  app.get('/post/:acc/inhalt', withAcc, async (req, res) => {
    const uid = int(req.query.uid, 1, 2 ** 32, 0)
    let msg
    try { msg = await readMessage(req.acc, req.folder, uid, { markSeen: false }) } catch (e) { return res.status(500).type('text/plain').send(errText(e)) }
    if (!msg) return res.status(404).type('text/plain').send('Nicht gefunden')
    const p = msg.parsed
    const html = p.html ? cleanMailHtml(p.html, attachmentsOf(p), { remote: req.query.bilder === '1' }).html : textToHtml(p.text)
    const imgs = req.query.bilder === '1' ? ' https: http:' : ''
    res.set({
      'Content-Security-Policy': `sandbox allow-popups allow-popups-to-escape-sandbox; default-src 'none'; img-src data:${imgs}; style-src 'unsafe-inline'; font-src data:; base-uri 'none'; form-action 'none'`,
      'X-Frame-Options': 'SAMEORIGIN',
      'Referrer-Policy': 'no-referrer'
    })
    res.type('html').send(`<!doctype html><html><head><meta charset="utf-8"><meta name="referrer" content="no-referrer"><base target="_blank"><style>body{margin:12px;font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;color:#1d1d1f;background:#fff;word-wrap:break-word}img{max-width:100%;height:auto}table{max-width:100%}</style></head><body>${html}</body></html>`)
  })

  // Anhänge (gefährliche gesperrt), Original als .eml
  app.get('/post/:acc/anhang', withAcc, async (req, res) => {
    const uid = int(req.query.uid, 1, 2 ** 32, 0)
    let msg
    try { msg = await readMessage(req.acc, req.folder, uid, { markSeen: false }) } catch (e) { return res.status(500).type('text/plain').send(errText(e)) }
    if (!msg) return res.status(404).type('text/plain').send('Nicht gefunden')
    res.set('Content-Security-Policy', "sandbox; default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'")
    if (req.query.teil === 'quelle') {
      res.set('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent((msg.parsed.subject || 'mail').replace(/[\\/:*?"<>|]+/g, '_').slice(0, 80))}.eml`)
      return res.type('message/rfc822').send(msg.source)
    }
    const a = attachmentsOf(msg.parsed)[int(req.query.teil, 0, 1000, -1)]
    if (!a) return res.status(404).type('text/plain').send('Anhang nicht gefunden')
    if (a.danger) { log('warn', `Gefährlicher Anhang gesperrt: ${a.filename} (${a.danger})`); return res.status(403).type('text/plain; charset=utf-8').send('Dieser Anhang ist gesperrt: ' + a.danger) }
    const view = req.query.ansehen === '1' && /^(application\/pdf|image\/(png|jpe?g|gif|webp))$/i.test(a.contentType)
    res.set('Content-Disposition', `${view ? 'inline' : 'attachment'}; filename*=UTF-8''${encodeURIComponent(a.filename)}`)
    res.type(view ? a.contentType : 'application/octet-stream').send(a.content)
  })

  app.post('/post/:acc/bilder', withAcc, (req, res) => {
    const sender = String(req.body.absender || '').toLowerCase()
    if (/^[^@\s]+@[^@\s]+$/.test(sender)) allowImages(sender)
    const to = String(req.body.zurueck || '')
    back(res, to.startsWith('/post/') ? to : `/post/${req.acc.id}`, { msg: `Bilder von ${sender} werden ab jetzt immer geladen.` })
  })

  // --- Aktionen (einzeln oder mehrere) ---
  app.post('/post/:acc/aktion', withAcc, async (req, res) => {
    const acc = req.acc
    const to0 = String(req.body.zurueck || '')
    const to = to0.startsWith('/post/') && !to0.startsWith('//') ? to0.replace(/[?&](ok|fehler)=[^&]*/g, '') : `/post/${acc.id}?${q({ ordner: req.folder })}`
    const uids = [].concat(req.body.uids || []).map(x => int(x, 1, 2 ** 32, 0)).filter(Boolean).slice(0, 500)
    if (!uids.length) return back(res, to, { err: 'Keine Mail ausgewählt.' })
    const safe = (v) => { v = String(v || ''); return v.startsWith(`/post/${acc.id}?`) ? v.replace(/[?&](ok|fehler)=[^&]*/g, '') : '' }
    // nach Verschieben/Löschen aus der geöffneten Mail: nächste Mail öffnen, sonst zurück zur Liste
    const listUrl = safe(req.body.weiter) || safe(req.body.liste) || `/post/${acc.id}?${q({ ordner: req.folder })}`
    try {
      switch (req.body.aktion) {
        case 'gelesen': await setFlags(acc, req.folder, uids, '\\Seen', true); break
        case 'ungelesen': await setFlags(acc, req.folder, uids, '\\Seen', false); uids.forEach(u => forgetCached(acc, req.folder, u)); return back(res, safe(req.body.liste) || to.replace(/[?&]uid=\d+/, ''), { msg: 'Als ungelesen markiert.' })
        case 'markieren': await setFlags(acc, req.folder, uids, '\\Flagged', true); break
        case 'entmarkieren': await setFlags(acc, req.folder, uids, '\\Flagged', false); break
        case 'harmlos': {
          await setFlags(acc, req.folder, uids, ['\\Flagged', '$Phishing'], false)
          const sender = String(req.body.absender || '').toLowerCase()
          if (sender.includes('@')) trustSender(sender, 'ui')
          uids.forEach(u => forgetCached(acc, req.folder, u))
          return back(res, to, { msg: 'Warnung entfernt, Absender gilt als vertrauenswürdig.' })
        }
        case 'verschieben': {
          const dest = String(req.body.ziel || '')
          if (!req.folders.some(f => f.path === dest)) return back(res, to, { err: 'Bitte einen Zielordner wählen.' })
          await moveMessages(acc, req.folder, uids, dest)
          return back(res, listUrl, { msg: `${uids.length} Mail(s) verschoben${/sortiert/i.test(dest) ? ' – Postwart lernt daraus beim nächsten Durchlauf' : ''}.` })
        }
        case 'spam': {
          const cfg = getConfig()
          const dest = await withMail(acc, (client) => ensurePath(client, categoryPath(cfg, categoryById('spam', cfg))))
          await moveMessages(acc, req.folder, uids, dest)
          folderCache.delete(`${req.session.userId}:${acc.id}`)
          return back(res, listUrl, { msg: `${uids.length} Mail(s) als Spam verschoben.` })
        }
        case 'loeschen': {
          const r = await deleteMessages(acc, req.folder, uids)
          return back(res, listUrl, { msg: r.trash ? `${uids.length} Mail(s) in den Papierkorb gelegt.` : `${uids.length} Mail(s) endgültig gelöscht.` })
        }
        default: return back(res, to, { err: 'Unbekannte Aktion.' })
      }
      back(res, to, { msg: 'Erledigt.' })
    } catch (e) { back(res, to, { err: errText(e) }) }
  })
}
