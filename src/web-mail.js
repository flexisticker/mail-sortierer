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
      const list = await folders(req, acc, req.method === 'GET' && req.path.endsWith('/' + acc.id))
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
    if (!a) return res.send(page({ title: 'Postfach', session: req.session, path: '/post', body: '<h1>Postfach</h1><p>Noch kein Postfach eingetragen.</p><a class="btn primary" href="/einstellungen#postfaecher">Postfach eintragen</a>' }))
    res.redirect(`/post/${a.id}`)
  })

  const sidebar = (req) => {
    const accs = listAccounts()
    return `<aside class="mail-side"><details class="mail-folders" open><summary>Ordner</summary>
      ${accs.length > 1 ? `<form method="get" action="/post/go" class="acc-pick"><select name="postfach" data-autosubmit>${options(accs.map(a => [a.id, accountLabel(a)]), req.acc.id)}</select><noscript><button class="btn sm">Wechseln</button></noscript></form>` : `<div class="muted small acc-one">${esc(accountLabel(req.acc))}</div>`}
      ${req.session.features.webmail ? `<a class="btn primary block" href="/post/neu?postfach=${req.acc.id}">Neue Mail</a>` : ''}
      <a class="small sig-link" href="/signaturen">Signaturen</a>
      <ul>${req.folders.map(f => `<li class="d${Math.min(f.depth, 4)}"><a href="/post/${req.acc.id}?${q({ ordner: f.path })}"${f.path === req.folder ? ' class="on"' : ''}>${esc(f.name)}${f.unseen ? ` <b class="cnt">${f.unseen}</b>` : ''}</a></li>`).join('')}</ul>
    </details></aside>`
  }
  app.get('/post/go', (req, res) => res.redirect(`/post/${int(req.query.postfach, 1, 1e9, 0)}`))

  const moveTargets = (req) => req.folders.filter(f => f.path !== req.folder).map(f => [f.path, '  '.repeat(f.depth) + f.name])

  // --- Liste ---
  app.get('/post/:acc', withAcc, async (req, res) => {
    const s = req.session
    const seite = int(req.query.seite, 1, 100000, 1)
    const query = String(req.query.q || '').trim().slice(0, 100)
    let data
    try { data = await listMessages(req.acc, req.folder, { page: seite, per: PER, q: query }) } catch (e) { return back(res, `/post/${req.acc.id}`, { err: errText(e) }) }
    const fname = (req.folders.find(f => f.path === req.folder) || {}).name || req.folder
    const here = req.originalUrl
    const pages = Math.max(1, Math.ceil(data.total / PER))
    const link = (p) => `/post/${req.acc.id}?${q({ ordner: req.folder, q: query, seite: p })}`
    const body = `<div class="mail-layout">${sidebar(req)}
    <section class="mail-main"${query ? '' : ' data-refresh="120"'}>
      <div class="mail-head"><h1>${esc(fname)} <span class="muted small">${data.total} Mails</span></h1>
        <form method="get" action="/post/${req.acc.id}" class="row"><input type="hidden" name="ordner" value="${esc(req.folder)}"><input name="q" value="${esc(query)}" placeholder="Suchen (Absender, Betreff, Text)" maxlength="100"><button class="btn">Suchen</button>${query ? `<a class="btn ghost" href="${esc(link(1))}">✕</a>` : ''}</form></div>
      <form method="post" action="/post/${req.acc.id}/aktion" id="mbulk">${csrf(s)}<input type="hidden" name="ordner" value="${esc(req.folder)}"><input type="hidden" name="zurueck" value="${esc(here)}">
      <div class="mail-tools row wrap">
        <label class="check"><input type="checkbox" data-all="msel" aria-label="Alle wählen"></label>
        <button class="btn sm" name="aktion" value="gelesen">Gelesen</button><button class="btn sm" name="aktion" value="ungelesen">Ungelesen</button>
        <button class="btn sm" name="aktion" value="markieren">Fähnchen</button>
        <select name="ziel" aria-label="Verschieben nach"><option value="">Verschieben nach …</option>${options(moveTargets(req), '')}</select><button class="btn sm" name="aktion" value="verschieben">Verschieben</button>
        <button class="btn sm" name="aktion" value="spam">Spam</button>
        <button class="btn sm ghost" name="aktion" value="loeschen" data-confirm="Ausgewählte Mails löschen (in den Papierkorb)?">Löschen</button>
      </div>
      <ul class="mlist">${data.items.map(m => `<li class="${m.seen ? '' : 'unread'}${m.danger ? ' danger' : ''}">
        <input type="checkbox" name="uids" value="${m.uid}" class="msel" aria-label="Auswählen">
        <a href="/post/${req.acc.id}/lesen?${q({ ordner: req.folder, uid: m.uid })}">
          <span class="mfrom">${m.flagged ? '<span class="flag" title="Fähnchen">⚑</span> ' : ''}${m.danger ? '<span class="pill bad">⚠ Phishing?</span> ' : ''}${esc(/gesendet|sent|entw|draft/i.test(fname) ? 'An: ' + who(m.to) : who(m.from))}</span>
          <span class="msubj">${m.answered ? '<span title="beantwortet">↩</span> ' : ''}${esc(m.subject || '(ohne Betreff)')}</span>
          <span class="mmeta">${m.att ? '📎 ' : ''}${fmtShort(m.date)}</span></a></li>`).join('') || `<li class="muted empty">${query ? 'Nichts gefunden.' : 'Keine Mails in diesem Ordner.'}</li>`}</ul>
      </form>
      <div class="pager">${seite > 1 ? `<a class="btn sm" href="${esc(link(seite - 1))}">‹ neuere</a>` : ''} Seite ${seite} von ${pages} ${seite < pages ? `<a class="btn sm" href="${esc(link(seite + 1))}">ältere ›</a>` : ''}</div>
    </section></div>`
    res.send(page({ title: fname, body, session: s, path: '/post', full: true, ...flash(req) }))
  })

  // --- Lesen ---
  app.get('/post/:acc/lesen', withAcc, async (req, res) => {
    const s = req.session
    const uid = int(req.query.uid, 1, 2 ** 32, 0)
    let msg
    try { msg = await readMessage(req.acc, req.folder, uid) } catch (e) { return back(res, `/post/${req.acc.id}?${q({ ordner: req.folder })}`, { err: errText(e) }) }
    if (!msg) return back(res, `/post/${req.acc.id}?${q({ ordner: req.folder })}`, { err: 'Die Mail gibt es nicht mehr.' })
    const p = msg.parsed
    const from = (p.from && p.from.value && p.from.value[0]) || { name: '', address: '' }
    from.address = String(from.address || '').toLowerCase()
    const atts = attachmentsOf(p)
    const files = atts.filter(a => !(a.related && a.cid))
    const risk = assessForView(p, from)
    const flagged = msg.flags.includes('\\Flagged')
    const phishFlag = msg.flags.includes('$Phishing')
    const back2 = `/post/${req.acc.id}?${q({ ordner: req.folder })}`
    const images = req.query.bilder === '1' || imagesAllowed(from.address)
    const cleaned = p.html ? cleanMailHtml(p.html, atts) : null
    const act = (aktion, label, cls = 'btn sm', confirm = '') => `<button class="${cls}" name="aktion" value="${aktion}"${confirm ? ` data-confirm="${esc(confirm)}"` : ''}>${label}</button>`
    const body = `<div class="mail-layout">${sidebar(req)}
    <section class="mail-main">
      <div class="row wrap mail-actions">
        <a class="btn sm" href="${esc(back2)}">‹ Zurück</a>
        ${isDrafts(req) ? `<a class="btn sm primary" href="/post/neu?${q({ postfach: req.acc.id, ordner: req.folder, uid, art: 'entwurf' })}">Entwurf bearbeiten</a>` : ''}
        ${s.features.webmail && !isDrafts(req) ? `<a class="btn sm primary" href="/post/neu?${q({ postfach: req.acc.id, ordner: req.folder, uid, art: 'antwort' })}">Antworten</a>
        <a class="btn sm" href="/post/neu?${q({ postfach: req.acc.id, ordner: req.folder, uid, art: 'alle' })}">Allen antworten</a>
        <a class="btn sm" href="/post/neu?${q({ postfach: req.acc.id, ordner: req.folder, uid, art: 'weiter' })}">Weiterleiten</a>` : ''}
        <form method="post" action="/post/${req.acc.id}/aktion" class="row wrap inline">${csrf(s)}<input type="hidden" name="ordner" value="${esc(req.folder)}"><input type="hidden" name="uids" value="${uid}"><input type="hidden" name="zurueck" value="${esc(back2)}">
          ${act(flagged ? 'entmarkieren' : 'markieren', flagged ? 'Fähnchen weg' : 'Fähnchen')}
          ${act('ungelesen', 'Ungelesen')}
          <select name="ziel" aria-label="Verschieben nach"><option value="">Verschieben nach …</option>${options(moveTargets(req), '')}</select>${act('verschieben', 'Verschieben')}
          ${act('spam', 'Spam')}
          ${act('loeschen', 'Löschen', 'btn sm ghost', 'Mail löschen (in den Papierkorb)?')}
        </form>
      </div>
      ${risk.level === 'bad' || phishFlag ? `<div class="alert bad"><b>⚠ Vorsicht – diese Mail ist verdächtig.</b> Keine Links anklicken, keine Anhänge öffnen, keine Daten eingeben.<ul>${risk.reasons.slice(0, 6).map(r => `<li>${esc(r)}</li>`).join('')}</ul>
        <form method="post" action="/post/${req.acc.id}/aktion" class="inline">${csrf(s)}<input type="hidden" name="ordner" value="${esc(req.folder)}"><input type="hidden" name="uids" value="${uid}"><input type="hidden" name="zurueck" value="${esc(req.originalUrl)}"><input type="hidden" name="absender" value="${esc(from.address)}">
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
          <a class="btn sm" href="${esc(req.originalUrl.replace(/&bilder=1/, '') + '&bilder=1')}">Bilder laden</a>
          <form method="post" action="/post/${req.acc.id}/bilder" class="inline">${csrf(s)}<input type="hidden" name="absender" value="${esc(from.address)}"><input type="hidden" name="zurueck" value="${esc(req.originalUrl)}"><button class="btn sm ghost">Immer bei ${esc(from.address)}</button></form></div>` : ''}
        <iframe class="mbody" title="Inhalt der Mail" sandbox="allow-popups allow-popups-to-escape-sandbox" referrerpolicy="no-referrer" src="/post/${req.acc.id}/inhalt?${q({ ordner: req.folder, uid, bilder: images ? 1 : '' })}"></iframe>
        <p class="muted small"><a href="/post/${req.acc.id}/anhang?${q({ ordner: req.folder, uid, teil: 'quelle' })}">Original herunterladen (.eml)</a></p>
      </article>
    </section></div>`
    res.send(page({ title: p.subject || 'Mail', body, session: s, path: '/post', full: true, ...flash(req) }))
  })

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
    const listUrl = `/post/${acc.id}?${q({ ordner: req.folder })}`
    try {
      switch (req.body.aktion) {
        case 'gelesen': await setFlags(acc, req.folder, uids, '\\Seen', true); break
        case 'ungelesen': await setFlags(acc, req.folder, uids, '\\Seen', false); uids.forEach(u => forgetCached(acc, req.folder, u)); return back(res, listUrl, { msg: 'Als ungelesen markiert.' })
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
