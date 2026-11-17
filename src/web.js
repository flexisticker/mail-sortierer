// Weboberfläche (nur Heimnetz): Übersicht, Mails mit Korrektur, Gelerntes, Protokoll, Einstellungen.
import express from 'express'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { db, now, log } from './db.js'
import { hasUsers, createUser, login, logout, sessionFor, verifyPassword, changePassword } from './auth.js'
import { getConfig, saveConfig, activeCategories, targetLabel, cleanFolderName, DEFAULT_CONFIG } from './config.js'
import { setSecret, hasSecret } from './secrets.js'
import { page, esc, csrf, fmtDate, options, STATUS_LABEL, SOURCE_LABEL } from './html.js'
import { runOnce, isRunning, getStatus, correct, confirm, undo, requeueKept } from './worker.js'
import { withClient, listFolders } from './imap.js'
import { listModels } from './ollama.js'
import { classify } from './classify.js'

const PUBLIC = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'public')
const COOKIE = 'ms_sitzung'

function cookie (req, name) {
  const m = String(req.headers.cookie || '').split(/;\s*/).find(c => c.startsWith(name + '='))
  return m ? decodeURIComponent(m.slice(name.length + 1)) : ''
}

function back (res, to, { msg, err } = {}) {
  const u = new URL(to, 'http://x')
  if (msg) u.searchParams.set('ok', String(msg).slice(0, 300))
  if (err) u.searchParams.set('fehler', String(err).slice(0, 300))
  res.redirect(303, u.pathname + u.search + u.hash)
}

const int = (v, min, max, def) => { const n = Math.round(Number(v)); return Number.isFinite(n) ? Math.min(max, Math.max(min, n)) : def }
const errText = (e) => String((e && (e.responseText || e.message)) || e).slice(0, 300)

export function createApp () {
  const app = express()
  app.disable('x-powered-by')
  app.set('trust proxy', false)

  app.use((req, res, next) => {
    res.set({
      'Content-Security-Policy': "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'",
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'same-origin',
      'X-Frame-Options': 'DENY',
      'Cache-Control': 'no-store'
    })
    next()
  })

  app.get('/health', (req, res) => res.json({ ok: true, id: 'mail-sortierer' }))
  app.use(express.static(PUBLIC, { index: false, maxAge: '1h', setHeaders: (res) => res.set('Cache-Control', 'public, max-age=3600') }))
  app.use(express.urlencoded({ extended: false, limit: '3mb', parameterLimit: 2000 }))

  // Sitzung + Schutz gegen fremde Formulare (Origin + CSRF-Feld)
  app.use((req, res, next) => {
    req.session = sessionFor(cookie(req, COOKIE))
    if (req.method === 'POST') {
      const origin = req.headers.origin
      if (origin && origin !== 'null') {
        try { if (new URL(origin).host !== req.headers.host) return res.status(403).send('Fremde Herkunft abgelehnt') } catch { return res.status(403).send('Ungültige Herkunft') }
      }
      if (req.session && req.body.csrf !== req.session.csrf) return res.status(403).send('Sicherheitsprüfung fehlgeschlagen – Seite neu laden.')
    }
    next()
  })

  const flash = (req) => ({ msg: req.query.ok, err: req.query.fehler })

  // --- Ersteinrichtung & Anmeldung ---
  app.get('/einrichten', (req, res) => {
    if (hasUsers()) return res.redirect('/anmelden')
    res.send(page({
      title: 'Einrichten', ...flash(req),
      body: `<section class="card narrow"><h1>Willkommen</h1>
      <p>Lege das Konto für die Oberfläche an. Es gibt nur dieses eine Konto.</p>
      <form method="post" action="/einrichten" class="form">
        <label>Benutzername<input name="name" required maxlength="40" autocomplete="username" value="michael"></label>
        <label>Passwort (mind. 10 Zeichen)<input name="pw" type="password" required minlength="10" autocomplete="new-password"></label>
        <label>Passwort wiederholen<input name="pw2" type="password" required minlength="10" autocomplete="new-password"></label>
        <button class="btn primary">Konto anlegen</button></form></section>`
    }))
  })
  app.post('/einrichten', async (req, res) => {
    if (hasUsers()) return res.redirect('/anmelden')
    const name = String(req.body.name || '').trim().slice(0, 40)
    if (!name) return back(res, '/einrichten', { err: 'Benutzername fehlt.' })
    if (String(req.body.pw || '').length < 10) return back(res, '/einrichten', { err: 'Passwort zu kurz (mind. 10 Zeichen).' })
    if (req.body.pw !== req.body.pw2) return back(res, '/einrichten', { err: 'Die Passwörter stimmen nicht überein.' })
    await createUser(name, req.body.pw)
    log('info', `Konto „${name}“ angelegt`)
    back(res, '/anmelden', { msg: 'Konto angelegt – bitte anmelden.' })
  })

  app.get('/anmelden', (req, res) => {
    if (!hasUsers()) return res.redirect('/einrichten')
    if (req.session) return res.redirect('/')
    res.send(page({
      title: 'Anmelden', ...flash(req),
      body: `<section class="card narrow"><h1>Anmelden</h1>
      <form method="post" action="/anmelden" class="form">
        <label>Benutzername<input name="name" required autocomplete="username" autofocus></label>
        <label>Passwort<input name="pw" type="password" required autocomplete="current-password"></label>
        <button class="btn primary">Anmelden</button></form></section>`
    }))
  })
  app.post('/anmelden', async (req, res) => {
    const r = await login(String(req.body.name || '').trim(), String(req.body.pw || ''), req.socket.remoteAddress || '')
    if (r.error) return back(res, '/anmelden', { err: r.error })
    res.set('Set-Cookie', `${COOKIE}=${encodeURIComponent(r.token)}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${30 * 86400}`)
    res.redirect(303, '/')
  })
  app.post('/abmelden', (req, res) => {
    logout(cookie(req, COOKIE))
    res.set('Set-Cookie', `${COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`)
    res.redirect(303, '/anmelden')
  })

  // Ab hier nur angemeldet
  app.use((req, res, next) => {
    if (!hasUsers()) return res.redirect('/einrichten')
    if (!req.session) return req.method === 'GET' ? res.redirect('/anmelden') : res.status(401).send('Bitte anmelden')
    next()
  })

  // --- Übersicht ---
  app.get('/', (req, res) => {
    const cfg = getConfig()
    const st = getStatus()
    const counts = Object.fromEntries(db.prepare('SELECT status, COUNT(*) n FROM mails GROUP BY status').all().map(r => [r.status, r.n]))
    const byCat = Object.fromEntries(db.prepare("SELECT decision, COUNT(*) n FROM mails WHERE status IN ('planned','moved') GROUP BY decision").all().map(r => [r.decision, r.n]))
    const today = db.prepare("SELECT COUNT(*) n FROM mails WHERE status = 'moved' AND moved_at >= ?").get(new Date(new Date().setHours(0, 0, 0, 0)).toISOString()).n
    const corrections = db.prepare("SELECT COUNT(*) n FROM examples").get().n
    const rules = db.prepare("SELECT COUNT(*) n FROM rules WHERE state = 'active'").get().n
    const suggestions = db.prepare("SELECT COUNT(*) n FROM rules WHERE state = 'suggest'").get().n
    const imapOk = !!(cfg.imap.host && cfg.imap.user && hasSecret('imapPassword'))
    const live = cfg.mode === 'live'
    const s = req.session
    const steps = [
      [imapOk, 'Postfach eintragen und testen', '/einstellungen#imap'],
      [!!st.lastOk, 'Ollama testen und ersten Durchlauf starten', '/einstellungen#ki'],
      [(counts.planned || 0) + (counts.moved || 0) > 0, 'Vorschläge im Probelauf ansehen und korrigieren', '/mails?status=planned'],
      [live, 'Scharf schalten – dann wird wirklich verschoben', '#modus']
    ]
    const body = `
    <h1>Übersicht</h1>
    ${steps.every(x => x[0]) ? '' : `<section class="card"><h2>Erste Schritte</h2><ol class="steps">${steps.map(([done, text, href]) => `<li class="${done ? 'done' : ''}"><a href="${href}">${esc(text)}</a></li>`).join('')}</ol></section>`}
    <div class="grid">
      <section class="card" id="modus"><h2>Modus</h2>
        <p class="big ${live ? 'live' : 'probe'}">${live ? 'Scharf – Mails werden verschoben' : 'Probelauf – es wird nichts verschoben'}</p>
        <p class="muted">${live ? 'Neue Mails landen automatisch in den Ordnern unter „' + esc(cfg.root) + '“. Gelöscht wird nie.' : 'Der Sortierer zeigt nur, was er tun würde. Prüfe die Vorschläge unter „Mails“ und korrigiere, was nicht passt.'}</p>
        <form method="post" action="/aktion/modus" class="row">${csrf(s)}
          ${live
            ? '<input type="hidden" name="mode" value="probe"><button class="btn">Zurück in den Probelauf</button>'
            : `<input type="hidden" name="mode" value="live"><button class="btn primary" data-confirm="Jetzt scharf schalten? Vorgemerkte Mails (${counts.planned || 0}) werden beim nächsten Durchlauf verschoben.">Scharf schalten</button>`}
        </form>
        <form method="post" action="/aktion/pause" class="row">${csrf(s)}<input type="hidden" name="paused" value="${cfg.paused ? '0' : '1'}">
          <button class="btn">${cfg.paused ? 'Zeitplan fortsetzen' : 'Zeitplan anhalten'}</button>${cfg.paused ? ' <span class="pill warn">angehalten</span>' : ''}</form>
      </section>
      <section class="card"><h2>Letzter Durchlauf</h2>
        ${isRunning() || st.running ? '<p class="pill info">läuft gerade …</p>' : ''}
        ${st.lastError ? `<div class="alert bad">${esc(st.lastError)}</div>` : ''}
        <dl class="facts">
          <dt>Zuletzt</dt><dd>${st.lastEnd ? fmtDate(st.lastEnd) : 'noch nie'}</dd>
          <dt>Ergebnis</dt><dd>${st.last ? `${st.last.read} gelesen, ${st.last.moved} verschoben, ${st.last.planned} vorgemerkt, ${st.last.corrections} Korrekturen` : '–'}</dd>
          <dt>Warten noch</dt><dd>${st.backlogLeft ? st.backlogLeft + ' Mails im Posteingang (werden nach und nach bearbeitet, nachts mehr)' : 'nichts'}</dd>
          <dt>Takt</dt><dd>alle ${cfg.intervalMin} Min., je Durchlauf ${cfg.batchDay} Mails (nachts ${cfg.batchNight})</dd>
        </dl>
        <form method="post" action="/aktion/lauf">${csrf(s)}<button class="btn primary"${imapOk ? '' : ' disabled'}>Jetzt durchlaufen</button></form>
      </section>
    </div>
    <div class="grid">
      <section class="card"><h2>Ordner</h2>
        <table class="tbl"><tbody>
        ${activeCategories(cfg).map(c => `<tr><td><a href="/mails?ordner=${c.id}">${esc(c.name)}</a></td><td class="num">${byCat[c.id] || 0}</td></tr>`).join('')}
        <tr><td><a href="/mails?status=kept">Bleibt im Posteingang</a></td><td class="num">${counts.kept || 0}</td></tr>
        </tbody></table>
        <p class="muted">Heute verschoben: ${today}</p>
      </section>
      <section class="card"><h2>Gelernt</h2>
        <dl class="facts"><dt>Feste Regeln</dt><dd>${rules}</dd><dt>Regel-Vorschläge</dt><dd>${suggestions}</dd><dt>Beispiele aus Korrekturen</dt><dd>${corrections}</dd></dl>
        <p class="muted">Ziehst du in Outlook eine Mail in einen anderen Ordner (oder zurück in den Posteingang), merkt sich der Sortierer das beim nächsten Durchlauf.</p>
        <a class="btn" href="/gelernt">Ansehen</a>
        <form method="post" action="/aktion/neu-pruefen" class="row">${csrf(s)}<button class="btn" data-confirm="Unsichere Mails im Posteingang beim nächsten Durchlauf neu einordnen lassen?">Unsichere neu einordnen</button></form>
      </section>
    </div>`
    res.send(page({ title: 'Übersicht', body, session: s, path: '/', ...flash(req) }))
  })

  app.post('/aktion/lauf', (req, res) => {
    runOnce('von Hand')
    back(res, '/', { msg: 'Durchlauf gestartet – die Seite in ein paar Sekunden neu laden.' })
  })
  app.post('/aktion/modus', (req, res) => {
    const mode = req.body.mode === 'live' ? 'live' : 'probe'
    saveConfig({ mode })
    log('info', mode === 'live' ? 'Scharf geschaltet' : 'Zurück in den Probelauf')
    if (mode === 'live') runOnce('scharf geschaltet')
    back(res, '/', { msg: mode === 'live' ? 'Scharf geschaltet – Ordner werden angelegt und Mails verschoben.' : 'Probelauf – es wird nichts mehr verschoben.' })
  })
  app.post('/aktion/pause', (req, res) => {
    saveConfig({ paused: req.body.paused === '1' })
    back(res, '/', { msg: req.body.paused === '1' ? 'Zeitplan angehalten.' : 'Zeitplan läuft wieder.' })
  })
  app.post('/aktion/neu-pruefen', (req, res) => {
    const n = requeueKept()
    back(res, '/', { msg: `${n} Mails werden beim nächsten Durchlauf neu eingeordnet.` })
  })

  // --- Mails ---
  app.get('/mails', (req, res) => {
    const cfg = getConfig()
    const s = req.session
    const status = String(req.query.status || '')
    const ordner = String(req.query.ordner || '')
    const quelle = String(req.query.quelle || '')
    const q = String(req.query.q || '').trim().slice(0, 100)
    const pageNo = int(req.query.seite, 1, 10000, 1)
    const where = []; const args = []
    if (status) { where.push('status = ?'); args.push(status) }
    if (ordner) { where.push('decision = ?'); args.push(ordner) }
    if (quelle) { where.push('source = ?'); args.push(quelle) }
    if (q) { where.push('(from_addr LIKE ? OR from_name LIKE ? OR subject LIKE ?)'); args.push(`%${q}%`, `%${q}%`, `%${q}%`) }
    const w = where.length ? 'WHERE ' + where.join(' AND ') : ''
    const total = db.prepare(`SELECT COUNT(*) n FROM mails ${w}`).get(...args).n
    const per = 100
    const rows = db.prepare(`SELECT * FROM mails ${w} ORDER BY COALESCE(date, created_at) DESC, id DESC LIMIT ? OFFSET ?`).all(...args, per, (pageNo - 1) * per)
    const targets = [['inbox', 'Posteingang'], ...activeCategories(cfg).map(c => [c.id, c.name])]
    const qs = (p) => { const u = new URLSearchParams({ ...(status && { status }), ...(ordner && { ordner }), ...(quelle && { quelle }), ...(q && { q }), seite: p }); return '/mails?' + u }
    const here = req.originalUrl
    const body = `
    <h1>Mails</h1>
    <form method="get" action="/mails" class="filters">
      <select name="status"><option value="">Alle Zustände</option>${options(Object.entries(STATUS_LABEL), status)}</select>
      <select name="ordner"><option value="">Alle Ziele</option>${options(targets, ordner)}</select>
      <select name="quelle"><option value="">Alle Quellen</option>${options(Object.entries(SOURCE_LABEL), quelle)}</select>
      <input name="q" value="${esc(q)}" placeholder="Absender oder Betreff">
      <button class="btn">Filtern</button>
    </form>
    <p class="muted">${total} Mails${cfg.mode !== 'live' ? ' · <b>Probelauf:</b> „Vorgemerkt“ heißt, so würde verschoben. Korrigieren hier lernt sofort mit.' : ''}</p>
    <form method="post" action="/mails/rueckgaengig" id="bulk">${csrf(s)}<input type="hidden" name="zurueck" value="${esc(here)}"></form>
    <div class="table-wrap"><table class="tbl mails">
      <thead><tr><th><input type="checkbox" data-all="sel" aria-label="Alle wählen"></th><th>Datum</th><th>Absender / Betreff</th><th>Einordnung</th><th>Richtig wäre</th></tr></thead>
      <tbody>
      ${rows.map(r => `<tr class="st-${esc(r.status)}">
        <td><input type="checkbox" name="ids" value="${r.id}" form="bulk" class="sel"></td>
        <td class="nowrap">${fmtDate(r.date || r.created_at)}</td>
        <td><div class="from">${esc(r.from_name || r.from_addr)} <span class="muted">&lt;${esc(r.from_addr)}&gt;</span></div>
          <div class="subj">${esc(r.subject || '(ohne Betreff)')}</div>
          ${r.snippet ? `<details><summary>Text</summary><div class="snip">${esc(String(r.snippet).slice(0, 700))}</div></details>` : ''}</td>
        <td><span class="pill cat">${esc(targetLabel(r.decision, cfg))}</span>
          <span class="pill st">${esc(STATUS_LABEL[r.status] || r.status)}</span>
          <div class="muted small">${esc(SOURCE_LABEL[r.source] || r.source || '')}${r.confidence != null && r.source === 'ki' ? ` · ${r.confidence} %` : ''}${r.reason ? ' · ' + esc(r.reason) : ''}</div>
          ${r.error ? `<div class="bad small">${esc(r.error)}</div>` : ''}</td>
        <td class="nowrap">${r.status === 'gone' ? '' : `<form method="post" action="/mails/${r.id}/korrektur" class="inline">${csrf(s)}<input type="hidden" name="zurueck" value="${esc(here)}">
            <select name="target" aria-label="Richtiger Ordner">${options(targets, r.decision)}</select><button class="btn sm">Ändern</button></form>
          ${['planned', 'moved', 'kept'].includes(r.status) && r.source !== 'correction' ? `<form method="post" action="/mails/${r.id}/passt" class="inline">${csrf(s)}<input type="hidden" name="zurueck" value="${esc(here)}"><button class="btn sm ghost" title="Richtig – zählt für eine feste Regel">passt</button></form>` : ''}`}</td>
      </tr>`).join('') || '<tr><td colspan="5" class="muted">Keine Mails.</td></tr>'}
      </tbody></table></div>
    <div class="row between">
      <button class="btn" form="bulk" data-confirm="Ausgewählte Mails zurück in den Posteingang (bzw. Vorschlag verwerfen)?">Ausgewählte rückgängig</button>
      <div class="pager">${pageNo > 1 ? `<a class="btn sm" href="${esc(qs(pageNo - 1))}">‹ zurück</a>` : ''} Seite ${pageNo} von ${Math.max(1, Math.ceil(total / per))} ${pageNo * per < total ? `<a class="btn sm" href="${esc(qs(pageNo + 1))}">weiter ›</a>` : ''}</div>
    </div>`
    res.send(page({ title: 'Mails', body, session: s, path: '/mails', wide: true, ...flash(req) }))
  })

  const safeBack = (v) => (typeof v === 'string' && v.startsWith('/') && !v.startsWith('//')) ? v.replace(/[?&](ok|fehler)=[^&]*/g, '') : '/mails'

  app.post('/mails/:id/korrektur', async (req, res) => {
    try {
      await correct(int(req.params.id, 1, 1e12, 0), String(req.body.target || ''))
      back(res, safeBack(req.body.zurueck), { msg: `Geändert auf „${targetLabel(String(req.body.target))}“ – gemerkt.` })
    } catch (e) { back(res, safeBack(req.body.zurueck), { err: errText(e) }) }
  })
  app.post('/mails/:id/passt', (req, res) => {
    try { confirm(int(req.params.id, 1, 1e12, 0)); back(res, safeBack(req.body.zurueck), { msg: 'Bestätigt – gemerkt.' }) } catch (e) { back(res, safeBack(req.body.zurueck), { err: errText(e) }) }
  })
  app.post('/mails/rueckgaengig', async (req, res) => {
    const ids = [].concat(req.body.ids || []).map(x => int(x, 1, 1e12, 0)).filter(Boolean).slice(0, 500)
    if (!ids.length) return back(res, safeBack(req.body.zurueck), { err: 'Keine Mails ausgewählt.' })
    try { const n = await undo(ids); back(res, safeBack(req.body.zurueck), { msg: `${n} rückgängig gemacht.` }) } catch (e) { back(res, safeBack(req.body.zurueck), { err: errText(e) }) }
  })

  // --- Gelernt ---
  app.get('/gelernt', (req, res) => {
    const cfg = getConfig()
    const s = req.session
    const rules = db.prepare("SELECT * FROM rules ORDER BY CASE state WHEN 'suggest' THEN 0 WHEN 'active' THEN 1 ELSE 2 END, updated_at DESC").all()
    const examples = db.prepare('SELECT * FROM examples ORDER BY id DESC LIMIT 150').all()
    const contacts = db.prepare('SELECT target, COUNT(*) n FROM contacts GROUP BY target').all()
    const targets = [['inbox', 'Posteingang'], ...activeCategories(cfg).map(c => [c.id, c.name])]
    const STATE = { active: 'gilt', suggest: 'Vorschlag', off: 'aus' }
    const ORIGIN = { outlook: 'aus Outlook', ui: 'in der Oberfläche', hand: 'von Hand angelegt', gemischt: 'gemischter Absender' }
    const body = `
    <h1>Gelernt</h1>
    <section class="card"><h2>Regeln</h2>
      <p class="muted">Eine Regel entsteht aus deinen Korrekturen. Nach ${cfg.ruleAfter} gleichen Korrekturen gilt sie fest (vorher „Vorschlag“). Schickt ein Absender Verschiedenes, wird die Regel ausgeschaltet – dann entscheidet die KI mit deinen Beispielen.</p>
      <div class="table-wrap"><table class="tbl">
      <thead><tr><th>Absender / Domain</th><th>Ziel</th><th>Zustand</th><th>Herkunft</th><th></th></tr></thead><tbody>
      ${rules.map(r => `<tr><td>${r.kind === 'domain' ? '<span class="pill">Domain</span> ' : ''}${esc(r.value)}</td>
        <td><form method="post" action="/regeln/${r.id}" class="inline">${csrf(s)}<input type="hidden" name="aktion" value="ziel"><select name="target">${options(targets, r.target)}</select><button class="btn sm">ok</button></form></td>
        <td><span class="pill ${r.state === 'active' ? 'good' : r.state === 'suggest' ? 'warn' : ''}">${STATE[r.state] || r.state}</span> <span class="muted small">${r.hits}×</span></td>
        <td class="small muted">${esc(ORIGIN[r.origin] || r.origin || '')} · ${fmtDate(r.updated_at)}</td>
        <td class="nowrap"><form method="post" action="/regeln/${r.id}" class="inline">${csrf(s)}
          ${r.state !== 'active' ? '<button class="btn sm" name="aktion" value="an">gilt</button>' : '<button class="btn sm" name="aktion" value="aus">aus</button>'}
          <button class="btn sm ghost" name="aktion" value="loeschen" data-confirm="Regel löschen?">löschen</button></form></td></tr>`).join('') || '<tr><td colspan="5" class="muted">Noch keine Regeln.</td></tr>'}
      </tbody></table></div>
      <h3>Regel von Hand anlegen</h3>
      <form method="post" action="/regeln" class="row wrap">${csrf(s)}
        <select name="kind"><option value="sender">Absender</option><option value="domain">Domain (z. B. dhl.de)</option></select>
        <input name="value" required placeholder="name@firma.de oder firma.de" maxlength="200">
        <select name="target">${options(targets, 'inbox')}</select>
        <button class="btn primary">Anlegen</button></form>
    </section>

    <section class="card"><h2>Bekannte Kontakte</h2>
      <p class="muted">Mails von bekannten Kunden landen immer in „${esc(targetLabel('kunden', cfg))}“. Bei Lieferanten bekommt die KI den Hinweis und entscheidet zwischen Lieferant und Rechnung. Einfügen: eine Liste mit E-Mail-Adressen oder eine CSV-Datei (z. B. Kundenliste aus Vedly) – erkannt wird jede Spalte mit E-Mail-Adressen.</p>
      <p>${contacts.map(c => `${esc(targetLabel(c.target, cfg))}: <b>${c.n}</b>`).join(' · ') || 'Noch keine Kontakte.'}</p>
      <form method="post" action="/kontakte" class="form">${csrf(s)}
        <label>Gehören zu<select name="target">${options([['kunden', targetLabel('kunden', cfg)], ['lieferanten', targetLabel('lieferanten', cfg)]], 'kunden')}</select></label>
        <label>CSV-Datei wählen<input type="file" accept=".csv,.txt,text/csv,text/plain" data-into="kontakte-text"></label>
        <label>… oder Inhalt einfügen<textarea name="text" id="kontakte-text" rows="5" placeholder="kunde@firma.de; Max Muster&#10;info@lieferant.de"></textarea></label>
        <button class="btn primary">Übernehmen</button></form>
      ${contacts.length ? `<form method="post" action="/kontakte/loeschen" class="row">${csrf(s)}<select name="target">${options(contacts.map(c => [c.target, targetLabel(c.target, cfg)]), '')}</select><button class="btn ghost" data-confirm="Diese Kontaktliste löschen?">Liste löschen</button></form>` : ''}
    </section>

    <section class="card"><h2>Beispiele für die KI</h2>
      <p class="muted">Jede Korrektur wird als Beispiel gemerkt. Bei ähnlichen Mails bekommt die KI bis zu ${cfg.maxExamples} davon mit.</p>
      <div class="table-wrap"><table class="tbl"><thead><tr><th>Datum</th><th>Absender / Betreff</th><th>Gehört nach</th><th></th></tr></thead><tbody>
      ${examples.map(e => `<tr><td class="nowrap">${fmtDate(e.created_at)}</td><td><div>${esc(e.from_addr)}</div><div class="muted small">${esc(e.subject)}</div></td>
        <td>${esc(targetLabel(e.target, cfg))}${e.previous && e.previous !== e.target ? ` <span class="muted small">(statt ${esc(targetLabel(e.previous, cfg))})</span>` : ''}</td>
        <td><form method="post" action="/beispiele/${e.id}/loeschen" class="inline">${csrf(s)}<button class="btn sm ghost">löschen</button></form></td></tr>`).join('') || '<tr><td colspan="4" class="muted">Noch keine Beispiele.</td></tr>'}
      </tbody></table></div>
    </section>`
    res.send(page({ title: 'Gelernt', body, session: s, path: '/gelernt', wide: true, ...flash(req) }))
  })

  const validTarget = (t, cfg = getConfig()) => t === 'inbox' || cfg.categories.some(c => c.id === t)

  app.post('/regeln', (req, res) => {
    const kind = req.body.kind === 'domain' ? 'domain' : 'sender'
    let value = String(req.body.value || '').trim().toLowerCase().replace(/^.*<|>.*$/g, '').replace(/^@/, '')
    const target = String(req.body.target || '')
    if (!validTarget(target)) return back(res, '/gelernt', { err: 'Unbekanntes Ziel.' })
    if (kind === 'sender' && !/^[^@\s]+@[^@\s]+\.[a-z0-9-]+$/i.test(value)) return back(res, '/gelernt', { err: 'Keine gültige Absender-Adresse.' })
    if (kind === 'domain') { value = value.split('@').pop(); if (!/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(value)) return back(res, '/gelernt', { err: 'Keine gültige Domain.' }) }
    const t = now()
    db.prepare(`INSERT INTO rules (kind, value, target, state, hits, conflicts, origin, created_at, updated_at) VALUES (?, ?, ?, 'active', 1, 0, 'hand', ?, ?)
      ON CONFLICT(kind, value) DO UPDATE SET target = excluded.target, state = 'active', origin = 'hand', updated_at = excluded.updated_at`).run(kind, value, target, t, t)
    log('info', `Regel von Hand: ${value} → ${targetLabel(target)}`)
    back(res, '/gelernt', { msg: 'Regel angelegt.' })
  })
  app.post('/regeln/:id', (req, res) => {
    const id = int(req.params.id, 1, 1e12, 0)
    const a = req.body.aktion
    if (a === 'loeschen') db.prepare('DELETE FROM rules WHERE id = ?').run(id)
    else if (a === 'an') db.prepare("UPDATE rules SET state = 'active', conflicts = 0, updated_at = ? WHERE id = ?").run(now(), id)
    else if (a === 'aus') db.prepare("UPDATE rules SET state = 'off', updated_at = ? WHERE id = ?").run(now(), id)
    else if (a === 'ziel') {
      if (!validTarget(String(req.body.target))) return back(res, '/gelernt', { err: 'Unbekanntes Ziel.' })
      db.prepare("UPDATE rules SET target = ?, state = 'active', origin = 'hand', updated_at = ? WHERE id = ?").run(String(req.body.target), now(), id)
    }
    back(res, '/gelernt', { msg: 'Gespeichert.' })
  })
  app.post('/beispiele/:id/loeschen', (req, res) => {
    db.prepare('DELETE FROM examples WHERE id = ?').run(int(req.params.id, 1, 1e12, 0))
    back(res, '/gelernt', { msg: 'Beispiel gelöscht.' })
  })
  app.post('/kontakte', (req, res) => {
    const target = req.body.target === 'lieferanten' ? 'lieferanten' : 'kunden'
    const text = String(req.body.text || '').slice(0, 3_000_000)
    const seen = new Set()
    const ins = db.prepare('INSERT INTO contacts (email, name, target, created_at) VALUES (?, ?, ?, ?) ON CONFLICT(email) DO UPDATE SET name = COALESCE(excluded.name, contacts.name), target = excluded.target')
    let n = 0
    db.exec('BEGIN')
    try {
      for (const line of text.split(/\r?\n/)) {
        const mails = line.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi) || []
        // Name = erstes Feld ohne @ (falls vorhanden)
        const name = (line.split(/[;,\t]/).map(x => x.replace(/^"|"$/g, '').trim()).find(x => x && !x.includes('@') && !/^\d+$/.test(x)) || '').slice(0, 120)
        for (const m of mails) {
          const e = m.toLowerCase()
          if (seen.has(e)) continue
          seen.add(e); ins.run(e, name || null, target, now()); n++
        }
      }
      db.exec('COMMIT')
    } catch (e) { db.exec('ROLLBACK'); return back(res, '/gelernt', { err: errText(e) }) }
    log('info', `${n} Kontakte als ${targetLabel(target)} übernommen`)
    back(res, '/gelernt', { msg: `${n} Adressen übernommen.` })
  })
  app.post('/kontakte/loeschen', (req, res) => {
    const r = db.prepare('DELETE FROM contacts WHERE target = ?').run(String(req.body.target || ''))
    back(res, '/gelernt', { msg: `${r.changes} Kontakte gelöscht.` })
  })

  // --- Protokoll ---
  app.get('/protokoll', (req, res) => {
    const rows = db.prepare('SELECT * FROM log ORDER BY id DESC LIMIT 400').all()
    const body = `<h1>Protokoll</h1><div class="table-wrap"><table class="tbl"><tbody>
      ${rows.map(r => `<tr class="lv-${esc(r.level)}"><td class="nowrap">${fmtDate(r.at)}</td><td>${esc(r.text)}</td></tr>`).join('') || '<tr><td class="muted">Noch keine Einträge.</td></tr>'}
      </tbody></table></div>`
    res.send(page({ title: 'Protokoll', body, session: req.session, path: '/protokoll', wide: true, ...flash(req) }))
  })

  // --- Einstellungen ---
  app.get('/einstellungen', (req, res) => {
    const cfg = getConfig()
    const s = req.session
    const models = (req.query.modelle || '').split(',').filter(Boolean)
    const chk = (v) => v ? ' checked' : ''
    const body = `
    <h1>Einstellungen</h1>
    <section class="card" id="imap"><h2>Postfach (IMAP)</h2>
      <p class="muted">Zugangsdaten deines Postfachs bei Alfahosting (dieselben wie in Outlook). Das Passwort wird verschlüsselt gespeichert und nie angezeigt.</p>
      <form method="post" action="/einstellungen/imap" class="form two">${csrf(s)}
        <label>Server<input name="host" value="${esc(cfg.imap.host)}" placeholder="z. B. alfa3xxx.alfahosting-server.de" maxlength="200"></label>
        <label>Port<input name="port" type="number" value="${esc(cfg.imap.port)}" min="1" max="65535"></label>
        <label>Benutzer (meist die Mail-Adresse)<input name="user" value="${esc(cfg.imap.user)}" autocomplete="off" maxlength="200"></label>
        <label>Passwort${hasSecret('imapPassword') ? ' <span class="pill good">gespeichert</span>' : ''}<input name="pass" type="password" autocomplete="new-password" placeholder="${hasSecret('imapPassword') ? 'leer lassen = unverändert' : ''}"></label>
        <label class="check"><input type="checkbox" name="secure" value="1"${chk(cfg.imap.secure)}> SSL/TLS (Port 993)</label>
        <label class="check"><input type="checkbox" name="allowSelfSigned" value="1"${chk(cfg.imap.allowSelfSigned)}> Zertifikat nicht prüfen (nur wenn nötig)</label>
        <div class="row span"><button class="btn primary" name="next" value="save">Speichern</button><button class="btn" name="next" value="test">Speichern &amp; testen</button></div>
      </form></section>

    <section class="card" id="ki"><h2>Lokale KI (Ollama)</h2>
      <p class="muted">Die KI läuft auf deinem Server. Empfohlen für die GTX 1060 (6 GB): <code>qwen2.5:7b</code>; bei 3 GB: <code>qwen2.5:3b</code>. Modell vorher in Ollama laden (<code>ollama pull qwen2.5:7b</code>).</p>
      <form method="post" action="/einstellungen/ki" class="form two">${csrf(s)}
        <label>Ollama-Adresse<input name="url" value="${esc(cfg.ollama.url)}" maxlength="200"></label>
        <label>Modell<input name="model" value="${esc(cfg.ollama.model)}" list="modelle" maxlength="100"><datalist id="modelle">${models.map(m => `<option value="${esc(m)}">`).join('')}</datalist></label>
        <label>Wartezeit je Mail (Sekunden)<input name="timeoutSec" type="number" value="${esc(cfg.ollama.timeoutSec)}" min="10" max="900"></label>
        <label>Kontextgröße (Tokens)<input name="numCtx" type="number" value="${esc(cfg.ollama.numCtx)}" min="1024" max="32768" step="512"></label>
        <div class="row span"><button class="btn primary" name="next" value="save">Speichern</button><button class="btn" name="next" value="test">Speichern &amp; testen</button></div>
      </form>
      ${models.length ? `<p class="small">Gefundene Modelle: ${models.map(esc).join(', ')}</p>` : ''}</section>

    <section class="card" id="ablauf"><h2>Ablauf</h2>
      <form method="post" action="/einstellungen/ablauf" class="form two">${csrf(s)}
        <label>Nachsehen alle … Minuten<input name="intervalMin" type="number" value="${cfg.intervalMin}" min="1" max="1440"></label>
        <label>Mails je Durchlauf tagsüber<input name="batchDay" type="number" value="${cfg.batchDay}" min="1" max="1000"></label>
        <label>Mails je Durchlauf nachts<input name="batchNight" type="number" value="${cfg.batchNight}" min="1" max="5000"></label>
        <label>Nacht von … bis … Uhr<span class="row"><input name="nightFrom" type="number" value="${cfg.nightFrom}" min="0" max="23"><input name="nightTo" type="number" value="${cfg.nightTo}" min="0" max="23"></span></label>
        <label class="check"><input type="checkbox" name="backlog" value="1"${chk(cfg.backlog)}> Altbestand im Posteingang mitbearbeiten</label>
        <label>Altbestand nur der letzten … Monate (0 = alle)<input name="backlogMonths" type="number" value="${cfg.backlogMonths}" min="0" max="240"></label>
        <label>Mindest-Sicherheit der KI (%)<input name="minConfidence" type="number" value="${cfg.minConfidence}" min="0" max="100"></label>
        <label>Mindest-Sicherheit für „Ausmisten“ (%)<input name="minConfidenceTrash" type="number" value="${cfg.minConfidenceTrash}" min="0" max="100"></label>
        <label>Feste Regel nach … gleichen Korrekturen<input name="ruleAfter" type="number" value="${cfg.ruleAfter}" min="1" max="10"></label>
        <label>Beispiele je Mail für die KI<input name="maxExamples" type="number" value="${cfg.maxExamples}" min="0" max="12"></label>
        <label class="span">Eigene Adressen (Mails davon bleiben im Posteingang, durch Komma getrennt)<input name="ownAddresses" value="${esc(cfg.ownAddresses)}" maxlength="1000"></label>
        <div class="row span"><button class="btn primary">Speichern</button></div>
      </form></section>

    <section class="card" id="ordner"><h2>Ordner</h2>
      <p class="muted">Die Ordner liegen unter „${esc(cfg.root)}“ in deinem Postfach und erscheinen in Outlook. Beschreibung = was die KI über den Ordner weiß. Wird ein Name geändert, legt der Sortierer einen neuen Ordner an; der alte bleibt (in Outlook umbenennen oder löschen).</p>
      <form method="post" action="/einstellungen/ordner" class="form">${csrf(s)}
        <label>Hauptordner<input name="root" value="${esc(cfg.root)}" maxlength="60" required></label>
        ${cfg.categories.map(c => `<fieldset class="cat"><legend>${esc(c.name)}</legend>
          <label>Name<input name="name_${c.id}" value="${esc(c.name)}" maxlength="60" required></label>
          <label>Beschreibung für die KI<textarea name="desc_${c.id}" rows="2" maxlength="600">${esc(c.desc)}</textarea></label>
          <label class="check"><input type="checkbox" name="off_${c.id}" value="1"${chk(c.off)}> nicht verwenden</label></fieldset>`).join('')}
        <div class="row"><button class="btn primary">Speichern</button><button class="btn ghost" name="reset" value="1" data-confirm="Namen und Beschreibungen auf die Vorgaben zurücksetzen?">Vorgaben</button></div>
      </form></section>

    <section class="card" id="konto"><h2>Konto</h2>
      <form method="post" action="/einstellungen/passwort" class="form two">${csrf(s)}
        <label>Aktuelles Passwort<input name="old" type="password" required autocomplete="current-password"></label>
        <label>Neues Passwort (mind. 10 Zeichen)<input name="pw" type="password" required minlength="10" autocomplete="new-password"></label>
        <div class="row span"><button class="btn">Passwort ändern</button></div>
      </form></section>`
    res.send(page({ title: 'Einstellungen', body, session: s, path: '/einstellungen', ...flash(req) }))
  })

  app.post('/einstellungen/imap', async (req, res) => {
    const b = req.body
    const cfg = saveConfig({ imap: {
      host: String(b.host || '').trim().replace(/^imaps?:\/\//, '').slice(0, 200),
      port: int(b.port, 1, 65535, 993),
      user: String(b.user || '').trim().slice(0, 200),
      secure: b.secure === '1',
      allowSelfSigned: b.allowSelfSigned === '1'
    } })
    if (b.pass) setSecret('imapPassword', String(b.pass).slice(0, 500))
    if (b.next !== 'test') return back(res, '/einstellungen#imap', { msg: 'Gespeichert.' })
    try {
      const info = await withClient(cfg, async (client) => {
        const folders = await listFolders(client)
        const st = await client.status('INBOX', { messages: true, unseen: true })
        return { folders, st, ns: client.namespace }
      })
      log('info', `IMAP-Test ok: ${info.st.messages} Mails im Posteingang`)
      back(res, '/einstellungen#imap', { msg: `Verbindung klappt: ${info.st.messages} Mails im Posteingang (${info.st.unseen} ungelesen), ${info.folders.length} Ordner. Trennzeichen „${(info.ns && info.ns.delimiter) || '?'}“${info.ns && info.ns.prefix ? `, Namensraum „${info.ns.prefix}“` : ''}.` })
    } catch (e) {
      back(res, '/einstellungen#imap', { err: 'IMAP-Test fehlgeschlagen: ' + (e.authenticationFailed ? 'Benutzer oder Passwort falsch.' : errText(e)) })
    }
  })

  app.post('/einstellungen/ki', async (req, res) => {
    const b = req.body
    const cfg = saveConfig({ ollama: {
      url: String(b.url || '').trim().slice(0, 200),
      model: String(b.model || '').trim().slice(0, 100),
      timeoutSec: int(b.timeoutSec, 10, 900, 120),
      numCtx: int(b.numCtx, 1024, 32768, 4096)
    } })
    if (b.next !== 'test') return back(res, '/einstellungen#ki', { msg: 'Gespeichert.' })
    let models = []
    try {
      models = await listModels(cfg)
      const names = models.map(m => m.name)
      if (!names.some(n => n === cfg.ollama.model || n === cfg.ollama.model + ':latest')) {
        return back(res, `/einstellungen?modelle=${encodeURIComponent(names.join(','))}#ki`, { err: `Ollama erreichbar, aber Modell „${cfg.ollama.model}“ ist nicht geladen. Auf dem Server: ollama pull ${cfg.ollama.model}` })
      }
      const t0 = Date.now()
      const d = await classify({
        msgid: 'test', from_addr: 'versand@paketdienst.example', from_name: 'Paketdienst', domain: 'paketdienst.example',
        subject: 'Ihre Sendung 00340434161094042557 ist unterwegs', hints: 'Absender ist eine automatische Adresse',
        snippet: 'Guten Tag, Ihre Sendung wurde heute an uns übergeben und wird voraussichtlich morgen zugestellt. Sendung verfolgen: …'
      }, { ...cfg, maxExamples: 0 })
      const ms = Date.now() - t0
      back(res, `/einstellungen?modelle=${encodeURIComponent(names.join(','))}#ki`, { msg: `KI antwortet in ${(ms / 1000).toFixed(1)} s. Testmail (Paketbenachrichtigung) → „${targetLabel(d.decision, cfg)}“ (${d.confidence} %): ${d.reason}` })
    } catch (e) {
      back(res, `/einstellungen?modelle=${encodeURIComponent(models.map(m => m.name).join(','))}#ki`, { err: 'KI-Test fehlgeschlagen: ' + errText(e) })
    }
  })

  app.post('/einstellungen/ablauf', (req, res) => {
    const b = req.body
    const d = DEFAULT_CONFIG
    saveConfig({
      intervalMin: int(b.intervalMin, 1, 1440, d.intervalMin),
      batchDay: int(b.batchDay, 1, 1000, d.batchDay),
      batchNight: int(b.batchNight, 1, 5000, d.batchNight),
      nightFrom: int(b.nightFrom, 0, 23, d.nightFrom),
      nightTo: int(b.nightTo, 0, 23, d.nightTo),
      backlog: b.backlog === '1',
      backlogMonths: int(b.backlogMonths, 0, 240, 0),
      minConfidence: int(b.minConfidence, 0, 100, d.minConfidence),
      minConfidenceTrash: int(b.minConfidenceTrash, 0, 100, d.minConfidenceTrash),
      ruleAfter: int(b.ruleAfter, 1, 10, d.ruleAfter),
      maxExamples: int(b.maxExamples, 0, 12, d.maxExamples),
      ownAddresses: String(b.ownAddresses || '').slice(0, 1000)
    })
    back(res, '/einstellungen#ablauf', { msg: 'Gespeichert.' })
  })

  app.post('/einstellungen/ordner', (req, res) => {
    const b = req.body
    if (b.reset === '1') {
      saveConfig({ categories: [] })
      return back(res, '/einstellungen#ordner', { msg: 'Vorgaben wiederhergestellt.' })
    }
    const cfg = getConfig()
    const root = cleanFolderName(b.root) || 'Sortiert'
    const cats = cfg.categories.map(c => ({ id: c.id, name: cleanFolderName(b['name_' + c.id]) || c.name, desc: String(b['desc_' + c.id] || c.desc).slice(0, 600), off: b['off_' + c.id] === '1' }))
    const names = cats.map(c => c.name.toLowerCase())
    if (new Set(names).size !== names.length) return back(res, '/einstellungen#ordner', { err: 'Zwei Ordner haben denselben Namen.' })
    saveConfig({ root, categories: cats })
    back(res, '/einstellungen#ordner', { msg: 'Gespeichert.' })
  })

  app.post('/einstellungen/passwort', async (req, res) => {
    const u = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId)
    if (!u || !(await verifyPassword(String(req.body.old || ''), u.hash))) return back(res, '/einstellungen#konto', { err: 'Aktuelles Passwort falsch.' })
    if (String(req.body.pw || '').length < 10) return back(res, '/einstellungen#konto', { err: 'Neues Passwort zu kurz.' })
    await changePassword(u.id, String(req.body.pw))
    res.set('Set-Cookie', `${COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`)
    back(res, '/anmelden', { msg: 'Passwort geändert – bitte neu anmelden.' })
  })

  app.use((req, res) => res.status(404).send(page({ title: 'Nicht gefunden', body: '<h1>Nicht gefunden</h1><p><a href="/">Zur Übersicht</a></p>', session: req.session })))
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    log('error', `Fehler bei ${req.method} ${req.path}: ${errText(err)}`)
    res.status(err.status === 413 ? 413 : 500).send(page({ title: 'Fehler', body: `<h1>Etwas ist schiefgegangen</h1><p>${esc(err.status === 413 ? 'Die Daten sind zu groß.' : 'Bitte noch einmal versuchen – Details im Protokoll.')}</p><p><a href="/">Zur Übersicht</a></p>`, session: req.session }))
  })
  return app
}
