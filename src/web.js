// Weboberfläche (nur Heimnetz): Übersicht, Mails mit Korrektur, Gelerntes, Protokoll, Einstellungen.
import express from 'express'
import path from 'node:path'
import fs from 'node:fs'
import crypto from 'node:crypto'
import os from 'node:os'
import { fileURLToPath } from 'node:url'
import { db, now, log, withUser } from './db.js'
import { hasUsers, sessionFor, getUser, featuresOf, verifyPassword, changePassword, checkSecondFactor, regenerateRecovery, recoveryLeft } from './auth.js'
import { COOKIE, sessionCookie, cookie, back, int, errText, flash } from './webutil.js'
import { shield, noteVisitor, isHome } from './shield.js'
import { registerLogin, mfaLocked } from './web-login.js'
import { registerAdmin } from './web-admin.js'
import { registerMail } from './web-mail.js'
import { registerCompose } from './web-compose.js'
import { PLATFORM, getConfig, saveConfig, companyList, activeCategories, targetLabel, cleanFolderName, DEFAULT_CONFIG } from './config.js'
import { setSecret, hasSecret } from './secrets.js'
import { page, esc, csrf, fmtDate, options, STATUS_LABEL, SOURCE_LABEL, manageHome } from './html.js'
import { reassessRecord, reassessRecords, suspectsFrom, runOnce, isRunning, getStatus, setStatus, getAccStatus, correct, confirm, undo, requeueKept } from './worker.js'
import { licenseState, activate, checkin, release } from './license.js'
import { listAccounts, getAccount, saveAccount, deleteAccount, setAccountMode, accountLabel, accountHasPassword, smtpOf, saveSmtp } from './accounts.js'
import { testSmtp } from './compose.js'
import { getSecret } from './secrets.js'
import { collecting, getInvoice, toAccounting, markPrivate, markNoInvoice, markOrder, reopen, release as releaseInvoice, editInvoice, forgetInvoiceLearning, applyYearSetting, checkScanDir, filePath, lexwareTest, monthName, STATUS as INV_STATUS } from './invoice.js'
import { withClient, listFolders } from './imap.js'
import { parseDnsServers, systemDnsServers, testBlocklists } from './security.js'
import { cleanupCfg, requestEmpty } from './cleanup.js'

const PUBLIC = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'public')

// Warnhinweise der Sicherheitsprüfung
function riskBox (r) {
  let reasons = []
  try { reasons = JSON.parse(r.risk_reasons || '[]') } catch { reasons = [] }
  if (!reasons.length) return ''
  const sev = r.decision === 'verdacht' ? 'bad' : 'warn'
  return `<details class="risk ${sev}"><summary>⚠ ${r.decision === 'verdacht' ? 'Verdacht' : r.decision === 'spam' ? 'Spam' : 'Auffällig'} (${Number(r.risk) || 0} Punkte) – keine Links anklicken, keine Anhänge öffnen</summary>
    <ul>${reasons.map(x => `<li>${esc(x)}</li>`).join('')}</ul></details>`
}

// Nach einer Aktion zur Zeile davor springen – so bleibt man an derselben Stelle der Liste
const anchor = (rows, i, p) => i > 0 ? `<input type="hidden" name="anker" value="${p}${rows[i - 1].id}">` : ''

// Seiten, die in jeder Anmelde-Stufe erreichbar sind
const STAGE_PAGE = { pw: '/anmelden/passwort', enroll: '/anmelden/einrichten-2fa', mfa: '/anmelden/code' }

export function createApp () {
  const app = express()
  app.disable('x-powered-by')
  // Hinter Nginx Proxy Manager: echte Besucher-IP und HTTPS nur von Proxys aus dem eigenen Netz übernehmen
  app.set('trust proxy', 'loopback, uniquelocal')

  app.use((req, res, next) => {
    res.set({
      'Content-Security-Policy': "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; form-action 'self'; frame-src 'self'; frame-ancestors 'self'; base-uri 'none'; object-src 'none'",
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'same-origin',
      'X-Frame-Options': 'SAMEORIGIN',
      'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=()',
      'Cache-Control': 'no-store'
    })
    if (req.secure) res.set('Strict-Transport-Security', 'max-age=31536000')
    noteVisitor(req)
    next()
  })

  // Hell/Dunkel je Gerät (Cookie pw_theme): steht schon im ausgelieferten HTML – kein Flackern, kein Skript im Kopf nötig
  app.use((req, res, next) => {
    const t = cookie(req, 'pw_theme')
    if (t === 'light' || t === 'dark') {
      const send = res.send
      res.send = function (b) { if (typeof b === 'string' && b.startsWith('<!doctype html>\n<html lang="de">')) b = b.replace('<html lang="de">', `<html lang="de" data-theme="${t}">`); return send.call(this, b) }
    }
    next()
  })
  app.get('/health', (req, res) => res.json({ ok: true, id: 'mail-sortierer' }))
  // robots.txt mit Köder: wer die verbotene Adresse trotzdem aufruft, ist ein Bot
  app.get('/robots.txt', (req, res) => res.type('text/plain').send('User-agent: *\nDisallow: /intern/\nDisallow: /\n'))

  // Angriffsschutz: gesperrte IPs abweisen, Fallen und Angriffsmuster erkennen (angemeldete Nutzer werden nicht geprüft)
  app.use(shield.middleware('app', {
    extraTraps: [
      { re: /^\/intern\/sicherung(\/|$)/i, kind: 'robots', detail: 'robots.txt-Köder' },
      { re: /^\/intern\/kontakt(\/|$)/i, kind: 'link', detail: 'unsichtbarer Link' }
    ],
    skip: (req) => { const s = sessionFor(cookie(req, COOKIE)); return !!(s && s.stage === 'full') },
    blocked: (req, res, b) => res.status(403).type('text/plain; charset=utf-8').send(`Zugriff vorübergehend gesperrt (bis ${new Date(b.until).toLocaleString('de-DE', { timeZone: 'Europe/Berlin' })}).`)
  }))

  app.use(express.static(PUBLIC, { index: false, maxAge: '1h', setHeaders: (res) => res.set('Cache-Control', 'public, max-age=3600') }))
  app.use(express.urlencoded({ extended: false, limit: '3mb', parameterLimit: 2000 }))

  // Sitzung + Schutz gegen fremde Formulare (Origin + CSRF-Feld)
  app.use((req, res, next) => {
    const tok = cookie(req, COOKIE)
    req.session = sessionFor(tok)
    if (req.session && req.session.renewed) res.append('Set-Cookie', sessionCookie(tok, true, req.secure))
    if (req.method === 'POST') {
      const origin = req.headers.origin
      if (origin && origin !== 'null') {
        try { if (new URL(origin).host !== req.headers.host) return res.status(403).send('Fremde Herkunft abgelehnt') } catch { return res.status(403).send('Ungültige Herkunft') }
      }
      // Anmelden/Einrichten brauchen kein Sitzungs-Feld (Herkunft wird oben geprüft) – sonst scheitert das Anmelden,
      // wenn noch eine gültige Sitzung besteht (wiederhergestellter Tab, zweites Fenster)
      if (req.path === '/anmelden' || req.path === '/einrichten') return next()
      // Formulare mit Dateien (Mail schreiben): CSRF-Feld prüft die Route nach dem Einlesen
      if (/^multipart\/form-data/i.test(req.headers['content-type'] || '')) {
        if (req.path !== '/post/senden') return res.status(415).send('Nicht erlaubt')
        req.csrfLater = true; return next()
      }
      if (req.session && (req.body || {}).csrf !== req.session.csrf) {
        // veraltete Seite: nichts ausführen, zurück zur Seite mit Hinweis statt einer Sackgasse
        let to = '/'
        try { const ref = new URL(req.headers.referer || ''); if (ref.host === req.headers.host) to = ref.pathname + ref.hash } catch { /* Startseite */ }
        return back(res, to, { err: 'Die Seite war veraltet – bitte noch einmal versuchen.' })
      }
    }
    next()
  })

  registerLogin(app)

  // Ab hier nur vollständig angemeldet (Passwort + 2FA). Alles läuft im Kontext des Nutzers (eigene Datenbank).
  app.use((req, res, next) => {
    if (!hasUsers()) return res.redirect('/einrichten')
    const s = req.session
    if (!s) return req.method === 'GET' ? res.redirect('/anmelden') : res.status(401).send('Bitte anmelden')
    if (s.stage !== 'full') return req.method === 'GET' ? res.redirect(STAGE_PAGE[s.stage] || '/anmelden') : res.status(401).send('Bitte Anmeldung abschließen')
    const user = getUser(s.userId)
    if (!user) return res.redirect('/anmelden')
    s.features = featuresOf(user)
    s.home = isHome(req)
    withUser(user, next)
  })
  // Reiter „Rechnungen“ nur zeigen, wenn er genutzt wird (Sammel-Postfach gewählt oder schon Rechnungen da)
  app.use((req, res, next) => {
    const s = req.session
    try { s.showInvoices = !!s.features.invoices && (Number(getConfig().invoices.accountId) > 0 || !!db.prepare('SELECT 1 FROM invoices LIMIT 1').get()) } catch { s.showInvoices = !!s.features.invoices }
    next()
  })

  registerAdmin(app)

  // Bereiche, die der Verwalter nicht freigegeben hat, sind gesperrt
  const needFeature = (f, label) => (req, res, next) => req.session.features[f] ? next() : res.status(403).send(page({ title: 'Nicht freigegeben', body: `<h1>Nicht freigegeben</h1><p>${esc(label)} ist für dein Konto nicht freigegeben. Frag den Verwalter.</p><p><a href="/">Zur Startseite</a></p>`, session: req.session }))
  app.use('/rechnungen', needFeature('invoices', 'Der Bereich Rechnungen'))
  app.use('/einstellungen/rechnungen', needFeature('invoices', 'Der Bereich Rechnungen'))
  app.use('/einstellungen/aufraeumen', needFeature('cleanup', 'Das Aufräumen'))
  app.use('/einstellungen/ordner', needFeature('folders', 'Das Bearbeiten der Ordner'))
  app.use('/lizenz', (req, res, next) => req.session.admin ? next() : res.status(403).send('Nur für den Verwalter'))
  app.use('/post', needFeature('webmail', 'Das Webmail'))
  app.use('/signaturen', needFeature('webmail', 'Das Webmail'))
  registerCompose(app) // vor registerMail: /post/neu und /post/senden dürfen nicht als Postfach-Nummer gelten
  registerMail(app)

  // Sortier-Seiten nur mit Freigabe „Sortierung sehen“ (Verwalter immer)
  for (const p of ['/uebersicht', '/mails', '/gelernt', '/protokoll', '/regeln', '/beispiele', '/kontakte', '/rechnungen-gelernt']) app.use(p, needFeature('manage', 'Die Sortier-Übersicht'))

  // Start: das Mail-Programm (ohne Postfach bzw. ohne Mail-Freigabe die Verwaltung)
  app.get('/', (req, res) => {
    const s = req.session
    if (s.features.webmail) return res.redirect('/post')
    res.redirect(manageHome(s))
  })

  // --- Übersicht ---
  app.get('/uebersicht', (req, res) => {
    const cfg = getConfig()
    const st = getStatus()
    const accSt = getAccStatus()
    const accounts = listAccounts()
    const counts = Object.fromEntries(db.prepare('SELECT status, COUNT(*) n FROM mails GROUP BY status').all().map(r => [r.status, r.n]))
    const byCat = Object.fromEntries(db.prepare("SELECT decision, COUNT(*) n FROM mails WHERE status IN ('planned','moved') GROUP BY decision").all().map(r => [r.decision, r.n]))
    const today = db.prepare("SELECT COUNT(*) n FROM mails WHERE status = 'moved' AND moved_at >= ?").get(new Date(new Date().setHours(0, 0, 0, 0)).toISOString()).n
    const corrections = db.prepare('SELECT COUNT(*) n FROM examples').get().n
    const rules = db.prepare("SELECT COUNT(*) n FROM rules WHERE state = 'active'").get().n
    const suggestions = db.prepare("SELECT COUNT(*) n FROM rules WHERE state = 'suggest'").get().n
    const openInv = db.prepare("SELECT COUNT(*) n FROM invoices WHERE status IN ('open','error')").get().n
    const checkInv = db.prepare("SELECT COUNT(*) n FROM invoices WHERE status IN ('open','error') AND suggestion = 'check'").get().n
    const sus = db.prepare("SELECT COUNT(*) n FROM mails WHERE decision = 'verdacht' AND created_at >= ?").get(new Date(Date.now() - 7 * 864e5).toISOString()).n
    const spamN = db.prepare("SELECT COUNT(*) n FROM mails WHERE decision = 'spam' AND created_at >= ?").get(new Date(Date.now() - 7 * 864e5).toISOString()).n
    const s = req.session
    const target = collecting(cfg)
    const anyLive = accounts.some(a => a.mode === 'live')
    const steps = [
      [accounts.length > 0, 'Postfächer eintragen und testen', '/einstellungen#postfaecher'],
      ...(s.admin ? [[!!st.lastOk, 'Gemeinsame KI (Ollama) testen und ersten Durchlauf starten', '/verwaltung/ki']] : [[!!st.lastOk, 'Ersten Durchlauf starten', '#durchlauf']]),
      ...(s.features.invoices ? [[!!target, 'Sammel-Postfach für Rechnungen wählen (rechnung@…)', '/einstellungen#rechnungen']] : []),
      [(counts.planned || 0) + (counts.moved || 0) > 0, 'Vorschläge im Probelauf ansehen und korrigieren', '/mails?status=planned'],
      [anyLive, 'Postfächer scharf schalten – dann wird wirklich verschoben', '#postfaecher']
    ]
    const L = licenseState()
    const body = `
    <h1>Übersicht</h1>
    ${!L.exempt && (L.warn || !L.full) && s.admin ? `<div class="alert ${L.full ? 'ok' : 'bad'}">${esc(L.message)} <a href="/einstellungen#lizenz">Lizenz</a></div>` : ''}
    ${steps.every(x => x[0]) ? '' : `<section class="card"><h2>Erste Schritte</h2><ol class="steps">${steps.map(([done, text, href]) => `<li class="${done ? 'done' : ''}"><a href="${href}">${esc(text)}</a></li>`).join('')}</ol></section>`}
    ${openInv && s.features.invoices ? `<section class="card"><h2>Rechnungen</h2><p><b>${openInv}</b> offene Rechnung(en) warten auf „Zur Buchhaltung“ oder „Privat“${checkInv ? `, davon <b>${checkInv}</b> zum Prüfen (Firma oder privat?)` : ''}.</p><a class="btn primary" href="/rechnungen">Rechnungen ansehen</a></section>` : ''}
    ${sus || spamN ? `<section class="card"><h2>Sicherheit (7 Tage)</h2><p>${sus ? `<b>${sus}</b> verdächtige Mail(s) nach „${esc(targetLabel('verdacht', cfg))}“ verschoben. ` : ''}${spamN ? `<b>${spamN}</b> Spam-Mail(s) aussortiert.` : ''}</p>
      <div class="row wrap">${sus ? '<a class="btn" href="/mails?ordner=verdacht">Verdacht ansehen</a>' : ''}${spamN ? '<a class="btn" href="/mails?ordner=spam">Spam ansehen</a>' : ''}</div></section>` : ''}
    <section class="card" id="postfaecher"><h2>Postfächer</h2>
      ${accounts.length ? `<div class="table-wrap"><table class="tbl"><tbody>
      ${accounts.map(a => { const x = accSt[a.id] || {}; return `<tr>
        <td><b>${esc(accountLabel(a))}</b>${target && target.id === a.id ? ' <span class="pill info">Rechnungen</span>' : ''}<div class="muted small">${esc(a.user)}${a.enabled ? '' : ' · ausgeschaltet'}</div>
          ${x.lastError ? `<div class="bad small">${esc(x.lastError)}</div>` : ''}</td>
        <td><span class="pill ${a.mode === 'live' ? 'good' : 'warn'}">${a.mode === 'live' ? 'Scharf' : 'Probelauf'}</span>
          <div class="muted small">${x.lastOk ? 'zuletzt ' + fmtDate(x.lastOk) : 'noch nicht gelaufen'}${x.left ? ` · ${x.left} warten` : ''}</div></td>
        <td class="nowrap"><form method="post" action="/aktion/modus" class="inline">${csrf(s)}<input type="hidden" name="account" value="${a.id}">
          ${a.mode === 'live'
            ? '<input type="hidden" name="mode" value="probe"><button class="btn sm">Probelauf</button>'
            : `<input type="hidden" name="mode" value="live"><button class="btn sm primary" data-confirm="${esc(accountLabel(a))} scharf schalten? Vorgemerkte Mails werden beim nächsten Durchlauf verschoben.">Scharf schalten</button>`}</form></td>
      </tr>` }).join('')}</tbody></table></div>` : '<p class="muted">Noch kein Postfach eingetragen.</p>'}
      <p class="muted small">Probelauf = nur anzeigen, was passieren würde. Scharf = verschieben (gelöscht wird nie).</p>
      <a class="btn" href="/einstellungen#postfaecher">Postfächer verwalten</a>
    </section>
    <div class="grid">
      <section class="card" id="durchlauf"><h2>Letzter Durchlauf</h2>
        ${isRunning() || st.running ? '<p class="pill info">läuft gerade …</p>' : ''}
        ${st.lastError ? `<div class="alert bad">${esc(st.lastError)}</div>` : ''}
        <dl class="facts">
          <dt>Zuletzt</dt><dd>${st.lastEnd ? fmtDate(st.lastEnd) : 'noch nie'}</dd>
          <dt>Ergebnis</dt><dd>${st.last ? `${st.last.read} gelesen, ${st.last.moved} verschoben, ${st.last.planned} vorgemerkt, ${st.last.corrections} Korrekturen${st.last.invoices ? `, ${st.last.invoices} Rechnungen` : ''}${st.last.scans ? `, ${st.last.scans} Scans` : ''}` : '–'}</dd>
          <dt>Warten noch</dt><dd>${st.backlogLeft ? st.backlogLeft + ' Mails (werden nach und nach bearbeitet, nachts mehr)' : 'nichts'}</dd>
          <dt>Takt</dt><dd>alle ${cfg.intervalMin} Min., je Durchlauf ${cfg.batchDay} Mails (nachts ${cfg.batchNight})</dd>
        </dl>
        <div class="row wrap">
          <form method="post" action="/aktion/lauf">${csrf(s)}<button class="btn primary"${accounts.length ? '' : ' disabled'}>Jetzt durchlaufen</button></form>
          <form method="post" action="/aktion/pause">${csrf(s)}<input type="hidden" name="paused" value="${cfg.paused ? '0' : '1'}"><button class="btn">${cfg.paused ? 'Zeitplan fortsetzen' : 'Zeitplan anhalten'}</button></form>
          ${cfg.paused ? '<span class="pill warn">angehalten</span>' : ''}
        </div>
      </section>
      <section class="card"><h2>Gelernt</h2>
        <dl class="facts"><dt>Feste Regeln</dt><dd>${rules}</dd><dt>Regel-Vorschläge</dt><dd>${suggestions}</dd><dt>Beispiele aus Korrekturen</dt><dd>${corrections}</dd></dl>
        <p class="muted">Ziehst du in Outlook eine Mail in einen anderen Ordner (oder zurück in den Posteingang), merkt sich Postwart das beim nächsten Durchlauf – in allen Postfächern.</p>
        <div class="row wrap"><a class="btn" href="/gelernt">Ansehen</a>
        <form method="post" action="/aktion/neu-pruefen">${csrf(s)}<button class="btn" data-confirm="Unsichere Mails im Posteingang beim nächsten Durchlauf neu einordnen lassen?">Unsichere neu einordnen</button></form></div>
      </section>
    </div>
    <section class="card"><h2>Ordner</h2>
      <table class="tbl"><tbody>
      ${activeCategories(cfg).map(c => `<tr><td><a href="/mails?ordner=${c.id}">${esc(c.name)}</a></td><td class="num">${byCat[c.id] || 0}</td></tr>`).join('')}
      <tr><td><a href="/mails?status=kept">Bleibt im Posteingang</a></td><td class="num">${counts.kept || 0}</td></tr>
      </tbody></table>
      <p class="muted">Heute verschoben: ${today}</p>
    </section>`
    res.send(page({ title: 'Übersicht', body, session: s, path: '/uebersicht', ...flash(req) }))
  })

  app.post('/aktion/lauf', (req, res) => {
    runOnce('von Hand')
    back(res, req.session.features.manage ? '/uebersicht' : '/einstellungen#postfaecher', { msg: 'Durchlauf gestartet – die Seite in ein paar Sekunden neu laden.' })
  })
  app.post('/aktion/modus', (req, res) => {
    const acc = getAccount(req.body.account)
    if (!acc) return back(res, manageHome(req.session), { err: 'Postfach nicht gefunden.' })
    const mode = req.body.mode === 'live' ? 'live' : 'probe'
    setAccountMode(acc.id, mode)
    log('info', `${accountLabel(acc)}: ${mode === 'live' ? 'scharf geschaltet' : 'zurück in den Probelauf'}`)
    if (mode === 'live') runOnce('scharf geschaltet')
    back(res, req.body.zurueck === 'einstellungen' || !req.session.features.manage ? '/einstellungen#postfaecher' : '/uebersicht#postfaecher', { msg: mode === 'live' ? `${accountLabel(acc)} ist scharf – Ordner werden angelegt und Mails verschoben.` : `${accountLabel(acc)}: Probelauf – es wird nichts mehr verschoben.` })
  })
  app.post('/aktion/pause', (req, res) => {
    saveConfig({ paused: req.body.paused === '1' })
    back(res, manageHome(req.session), { msg: req.body.paused === '1' ? 'Zeitplan angehalten.' : 'Zeitplan läuft wieder.' })
  })
  app.post('/aktion/neu-pruefen', (req, res) => {
    const n = requeueKept()
    back(res, '/uebersicht', { msg: `${n} Mails werden beim nächsten Durchlauf neu eingeordnet.` })
  })

  // --- Mails ---
  app.get('/mails', (req, res) => {
    const cfg = getConfig()
    const s = req.session
    const status = String(req.query.status || '')
    const ordner = String(req.query.ordner || '')
    const quelle = String(req.query.quelle || '')
    const konto = String(req.query.postfach || '')
    const q = String(req.query.q || '').trim().slice(0, 100)
    const accounts = listAccounts()
    const accName = Object.fromEntries(accounts.map(a => [a.id, accountLabel(a)]))
    const pageNo = int(req.query.seite, 1, 10000, 1)
    const where = []; const args = []
    if (status) { where.push('status = ?'); args.push(status) }
    if (ordner) { where.push('decision = ?'); args.push(ordner) }
    if (quelle) { where.push('source = ?'); args.push(quelle) }
    if (konto) { where.push('account_id = ?'); args.push(Number(konto)) }
    if (q) { where.push('(from_addr LIKE ? OR from_name LIKE ? OR subject LIKE ?)'); args.push(`%${q}%`, `%${q}%`, `%${q}%`) }
    const w = where.length ? 'WHERE ' + where.join(' AND ') : ''
    const total = db.prepare(`SELECT COUNT(*) n FROM mails ${w}`).get(...args).n
    const per = 100
    const rows = db.prepare(`SELECT * FROM mails ${w} ORDER BY COALESCE(date, created_at) DESC, id DESC LIMIT ? OFFSET ?`).all(...args, per, (pageNo - 1) * per)
    const targets = [['inbox', 'Posteingang'], ...activeCategories(cfg).map(c => [c.id, c.name])]
    const qs = (p) => { const u = new URLSearchParams({ ...(status && { status }), ...(ordner && { ordner }), ...(quelle && { quelle }), ...(konto && { postfach: konto }), ...(q && { q }), seite: p }); return '/mails?' + u }
    const here = req.originalUrl
    const body = `
    <h1>Sortierung</h1>
    <form method="get" action="/mails" class="filters">
      <select name="status"><option value="">Alle Zustände</option>${options(Object.entries(STATUS_LABEL), status)}</select>
      <select name="ordner"><option value="">Alle Ziele</option>${options(targets, ordner)}</select>
      <select name="quelle"><option value="">Alle Quellen</option>${options(Object.entries(SOURCE_LABEL), quelle)}</select>
      ${accounts.length > 1 ? `<select name="postfach"><option value="">Alle Postfächer</option>${options(accounts.map(a => [a.id, accountLabel(a)]), konto)}</select>` : ''}
      <input name="q" value="${esc(q)}" placeholder="Absender oder Betreff">
      <button class="btn">Filtern</button>
    </form>
    <p class="muted">${total} Mails${accounts.some(a => a.mode !== 'live') ? ' · <b>Probelauf:</b> „Vorgemerkt“ heißt, so würde verschoben. Korrigieren hier lernt sofort mit.' : ''}</p>
    <form method="post" action="/mails/rueckgaengig" id="bulk">${csrf(s)}<input type="hidden" name="zurueck" value="${esc(here)}"></form>
    <div class="table-wrap"><table class="tbl mails">
      <thead><tr><th><input type="checkbox" data-all="sel" aria-label="Alle wählen"></th><th>Datum</th><th>Absender / Betreff</th><th>Einordnung</th><th>Richtig wäre</th></tr></thead>
      <tbody>
      ${rows.map((r, i) => `<tr class="st-${esc(r.status)}" id="m${r.id}">
        <td><input type="checkbox" name="ids" value="${r.id}" form="bulk" class="sel"></td>
        <td class="nowrap">${fmtDate(r.date || r.created_at)}${accounts.length > 1 ? `<div class="muted small">${esc(accName[r.account_id] || '')}</div>` : ''}</td>
        <td><div class="from">${esc(r.from_name || r.from_addr)} <span class="muted">&lt;${esc(r.from_addr)}&gt;</span></div>
          <div class="subj">${esc(r.subject || '(ohne Betreff)')}</div>
          ${r.snippet ? `<details><summary>Text</summary><div class="snip">${esc(String(r.snippet).slice(0, 700))}</div></details>` : ''}</td>
        <td><span class="pill cat">${esc(targetLabel(r.decision, cfg))}</span>
          <span class="pill st">${esc(STATUS_LABEL[r.status] || r.status)}</span>
          <div class="muted small">${esc(SOURCE_LABEL[r.source] || r.source || '')}${r.confidence != null && r.source === 'ki' ? ` · ${r.confidence} %` : ''}${r.reason ? ' · ' + esc(r.reason) : ''}</div>
          ${r.error ? `<div class="bad small">${esc(r.error)}</div>` : ''}
          ${riskBox(r)}</td>
        <td class="nowrap">${r.status === 'gone' || (r.status === 'deleted' && !r.folder) ? '' : `<form method="post" action="/mails/${r.id}/korrektur" class="inline">${csrf(s)}${anchor(rows, i, 'm')}<input type="hidden" name="zurueck" value="${esc(here)}">
            <select name="target" aria-label="Richtiger Ordner">${options(targets, r.decision)}</select><button class="btn sm">Ändern</button></form>
          ${(r.decision === 'verdacht' || r.decision === 'spam') && r.status !== 'gone' ? `<form method="post" action="/mails/${r.id}/korrektur" class="inline">${csrf(s)}${anchor(rows, i, 'm')}<input type="hidden" name="zurueck" value="${esc(here)}"><input type="hidden" name="target" value="inbox"><input type="hidden" name="harmlos" value="1"><button class="btn sm" data-confirm="Absender ${esc(r.from_addr)} als vertrauenswürdig merken? Die Mail wird sofort neu eingeordnet.">ist harmlos</button></form>` : ''}
          ${['planned', 'moved', 'kept'].includes(r.status) && r.source !== 'correction' && r.source !== 'security' ? `<form method="post" action="/mails/${r.id}/passt" class="inline">${csrf(s)}${anchor(rows, i, 'm')}<input type="hidden" name="zurueck" value="${esc(here)}"><button class="btn sm ghost" title="Richtig – zählt für eine feste Regel">passt</button></form>` : ''}`}</td>
      </tr>`).join('') || '<tr><td colspan="5" class="muted">Keine Mails.</td></tr>'}
      </tbody></table></div>
    <div class="row between">
      <div class="row wrap">
      ${(() => { const ok = rows.filter(r => ['planned', 'moved', 'kept'].includes(r.status) && !['correction', 'security', 'own'].includes(r.source) && !String(r.reason || '').endsWith('✓')); return ok.length ? `<form method="post" action="/mails/passt-alle">${csrf(s)}<input type="hidden" name="zurueck" value="${esc(here)}">${ok.map(r => `<input type="hidden" name="ids" value="${r.id}">`).join('')}
        <button class="btn primary" data-confirm="Du hast diese Seite durchgesehen und alles, was du nicht geändert hast, ist richtig einsortiert? (${ok.length} Mails – zählt für Regeln und als Beispiele für die KI)">Seite geprüft – alles passt (${ok.length})</button></form>` : '' })()}
      <button class="btn" form="bulk" data-confirm="Ausgewählte Mails zurück in den Posteingang (bzw. Vorschlag verwerfen)?">Ausgewählte rückgängig</button>
      </div>
      <div class="pager">${pageNo > 1 ? `<a class="btn sm" href="${esc(qs(pageNo - 1))}">‹ zurück</a>` : ''} Seite ${pageNo} von ${Math.max(1, Math.ceil(total / per))} ${pageNo * per < total ? `<a class="btn sm" href="${esc(qs(pageNo + 1))}">weiter ›</a>` : ''}</div>
    </div>`
    res.send(page({ title: 'Sortierung', body, session: s, path: '/mails', wide: true, ...flash(req) }))
  })

  const withAnchor = (url, a) => /^[mr]\d{1,12}$/.test(String(a || '')) ? url.replace(/#.*$/, '') + '#' + a : url
  const safeBack = (v, a) => withAnchor((typeof v === 'string' && v.startsWith('/') && !v.startsWith('//')) ? v.replace(/[?&](ok|fehler)=[^&]*/g, '') : '/mails', a)

  app.post('/mails/:id/korrektur', async (req, res) => {
    try {
      if (req.body.harmlos === '1') {
        const id = int(req.params.id, 1, 1e12, 0)
        const sender = (db.prepare('SELECT from_addr FROM mails WHERE id = ?').get(id) || {}).from_addr || ''
        const r = await reassessRecord(id)
        if (suspectsFrom(sender, [id]).length) {
          const to = safeBack(req.body.zurueck, req.body.anker)
          return res.redirect(303, `/harmlos?${new URLSearchParams({ absender: sender, ziel: r[0] ? r[0].label : '', zurueck: to })}`)
        }
        return back(res, safeBack(req.body.zurueck, req.body.anker), { msg: r[0] ? `Absender gilt als vertrauenswürdig – neu eingeordnet: „${r[0].label}“.` : 'Absender gilt als vertrauenswürdig.' })
      }
      await correct(int(req.params.id, 1, 1e12, 0), String(req.body.target || ''))
      back(res, safeBack(req.body.zurueck, req.body.anker), { msg: `Geändert auf „${targetLabel(String(req.body.target))}“ – gemerkt.` })
    } catch (e) { back(res, safeBack(req.body.zurueck, req.body.anker), { err: errText(e) }) }
  })
  // --- Rückfrage nach „ist harmlos“: weitere Mails desselben Absenders mit neu einordnen? ---
  const safeTo = (v) => (typeof v === 'string' && v.startsWith('/') && !v.startsWith('//') && !v.includes('\\')) ? v.replace(/[?&](ok|fehler)=[^&]*/g, '') : '/'
  app.get('/harmlos', (req, res) => {
    const sender = String(req.query.absender || '').toLowerCase().slice(0, 200)
    const to = safeTo(String(req.query.zurueck || ''))
    const list = suspectsFrom(sender)
    if (!list.length) return res.redirect(303, to)
    const s = req.session
    const ziel = String(req.query.ziel || '').slice(0, 80)
    const body = `<section class="card narrow wide-narrow"><h1>Weitere Mails von diesem Absender?</h1>
      ${ziel ? `<div class="alert ok">Erledigt: Die Mail liegt jetzt in „${esc(ziel)}“, <b>${esc(sender)}</b> gilt als vertrauenswürdig.</div>` : ''}
      <p>Von <b>${esc(sender)}</b> liegen noch <b>${list.length}</b> Mail(s) in „${esc(targetLabel('verdacht'))}“ bzw. „${esc(targetLabel('spam'))}“. Sollen die gleich mit neu eingeordnet werden?</p>
      <form method="post" action="/harmlos" class="form">${csrf(s)}<input type="hidden" name="zurueck" value="${esc(to)}"><input type="hidden" name="absender" value="${esc(sender)}">
        <label class="check"><input type="checkbox" data-all="hsel" checked> <b>Alle auswählen</b></label>
        <ul class="hlist">${list.map(r => `<li><label class="check"><input type="checkbox" class="hsel" name="ids" value="${r.id}" checked> <span><b>${esc(r.subject || '(ohne Betreff)')}</b><br><span class="muted small">${fmtDate(r.date)} · ${esc(targetLabel(r.decision))}</span></span></label></li>`).join('')}</ul>
        <div class="row wrap"><button class="btn primary" name="aktion" value="alle">Ausgewählte neu einordnen</button><a class="btn ghost" href="${esc(to)}">Nein, nur diese eine</a></div>
      </form></section>`
    res.send(page({ title: 'Weitere Mails', body, session: s, path: '/post' }))
  })
  app.post('/harmlos', async (req, res) => {
    const to = safeTo(String(req.body.zurueck || ''))
    const sender = String(req.body.absender || '').toLowerCase()
    const allowed = new Set(suspectsFrom(sender).map(r => r.id))
    const ids = [].concat(req.body.ids || []).map(x => int(x, 1, 1e12, 0)).filter(id => allowed.has(id))
    if (!ids.length) return back(res, to, { msg: 'Nichts weiter geändert.' })
    try {
      const r = await reassessRecords(ids)
      const by = {}
      for (const x of r) by[x.label] = (by[x.label] || 0) + 1
      back(res, to, { msg: `${r.length} Mail(s) neu eingeordnet${r.length ? ': ' + Object.entries(by).map(([l, n]) => `${l} (${n})`).join(', ') : ''}.` })
    } catch (e) { back(res, to, { err: errText(e) }) }
  })

  app.post('/mails/:id/passt', (req, res) => {
    try { confirm(int(req.params.id, 1, 1e12, 0)); back(res, safeBack(req.body.zurueck, req.body.anker), { msg: 'Bestätigt – gemerkt.' }) } catch (e) { back(res, safeBack(req.body.zurueck, req.body.anker), { err: errText(e) }) }
  })
  app.post('/mails/passt-alle', (req, res) => {
    const ids = [].concat(req.body.ids || []).map(x => int(x, 1, 1e12, 0)).filter(Boolean).slice(0, 200)
    let n = 0
    for (const id of ids) { try { confirm(id); n++ } catch { /* übersprungen */ } }
    log('info', `${n} Mails als richtig bestätigt (Seite geprüft)`)
    back(res, safeBack(req.body.zurueck), { msg: `${n} Mails als richtig gemerkt – danke, das hilft der KI.` })
  })
  app.post('/mails/rueckgaengig', async (req, res) => {
    const ids = [].concat(req.body.ids || []).map(x => int(x, 1, 1e12, 0)).filter(Boolean).slice(0, 500)
    if (!ids.length) return back(res, safeBack(req.body.zurueck, req.body.anker), { err: 'Keine Mails ausgewählt.' })
    try { const n = await undo(ids); back(res, safeBack(req.body.zurueck, req.body.anker), { msg: `${n} rückgängig gemacht.` }) } catch (e) { back(res, safeBack(req.body.zurueck, req.body.anker), { err: errText(e) }) }
  })

  // --- Gelernt ---
  app.get('/gelernt', (req, res) => {
    const cfg = getConfig()
    const s = req.session
    const rules = db.prepare("SELECT * FROM rules ORDER BY CASE state WHEN 'suggest' THEN 0 WHEN 'active' THEN 1 ELSE 2 END, updated_at DESC").all()
    const examples = db.prepare('SELECT * FROM examples ORDER BY id DESC LIMIT 150').all()
    const invEx = db.prepare('SELECT * FROM inv_examples ORDER BY id DESC LIMIT 100').all()
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
      ${rules.map(r => `<tr><td>${r.kind === 'domain' ? '<span class="pill">Domain</span> ' : r.kind === 'trust' ? '<span class="pill good">vertrauenswürdig</span> ' : ''}${esc(r.value)}</td>
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

    <section class="card"><h2>Rechnungen – gelernt</h2>
      <p class="muted">Jede geprüfte Rechnung wird gemerkt: korrigierte Angaben (Lieferant, Worum geht’s, Firma, Datum …) und deine Entscheidung. Beim nächsten Beleg desselben Absenders übernimmt Postwart Lieferantenname und Firma und gibt der KI diese Beispiele mit.</p>
      <div class="table-wrap"><table class="tbl"><thead><tr><th>Datum</th><th>Absender</th><th>Gemerkt</th><th></th></tr></thead><tbody>
      ${invEx.map(e => `<tr><td class="nowrap">${fmtDate(e.created_at)}</td><td class="small">${esc(e.from_addr || 'Scan')}</td>
        <td><b>${esc(e.supplier || '?')}</b>${e.brand ? ` <span class="pill brand">${esc(e.brand)}</span>` : ''} <span class="pill">${esc({ business: 'geschäftlich', private: 'privat', noinvoice: 'keine Rechnung', edit: 'Angaben korrigiert' }[e.decision] || e.decision)}</span>
          <div class="muted small">${esc(e.content || '')}</div></td>
        <td><form method="post" action="/rechnungen-gelernt/${e.id}/loeschen" class="inline">${csrf(s)}<button class="btn sm ghost">vergessen</button></form></td></tr>`).join('') || '<tr><td colspan="4" class="muted">Noch nichts – kommt mit der ersten geprüften Rechnung.</td></tr>'}
      </tbody></table></div>
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
  app.post('/rechnungen-gelernt/:id/loeschen', (req, res) => {
    forgetInvoiceLearning(int(req.params.id, 1, 1e12, 0))
    back(res, '/gelernt', { msg: 'Vergessen.' })
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

  // --- Rechnungen ---
  app.get('/rechnungen', (req, res) => {
    const cfg = getConfig()
    const s = req.session
    const status = req.query.status === undefined ? 'open' : String(req.query.status)
    const jahr = String(req.query.jahr || '')
    const monat = String(req.query.monat || '')
    const q = String(req.query.q || '').trim().slice(0, 100)
    const zu = String(req.query.zuordnung || '')
    const companies = companyList(cfg)
    const where = []; const args = []
    if (zu === 'privat') where.push("(status = 'private' OR (status IN ('open','error') AND suggestion = 'private'))")
    else if (zu === 'pruefen') where.push("status IN ('open','error') AND suggestion = 'check'")
    else if (zu) { where.push('brand = ?'); args.push(zu) }
    if (status === 'open') where.push("status IN ('open', 'error')")
    else if (status) { where.push('status = ?'); args.push(status) }
    const ym = "COALESCE(NULLIF(substr(inv_date, 1, 7), ''), substr(created_at, 1, 7))"
    if (jahr) { where.push(`substr(${ym}, 1, 4) = ?`); args.push(jahr) }
    if (monat) { where.push(`substr(${ym}, 6, 2) = ?`); args.push(monat.padStart(2, '0')) }
    if (q) { where.push('(supplier LIKE ? OR number LIKE ? OR from_addr LIKE ? OR subject LIKE ? OR content LIKE ?)'); args.push(...Array(5).fill(`%${q}%`)) }
    const w = where.length ? 'WHERE ' + where.join(' AND ') : ''
    const rows = db.prepare(`SELECT * FROM invoices ${w} ORDER BY ${ym} DESC, inv_date DESC, id DESC LIMIT 500`).all(...args)
    const sum = rows.filter(r => r.amount != null && r.status !== 'duplicate' && r.status !== 'nodoc' && r.status !== 'order').reduce((a, r) => a + r.amount, 0)
    const counts = Object.fromEntries(db.prepare('SELECT status, COUNT(*) n FROM invoices GROUP BY status').all().map(r => [r.status, r.n]))
    const years = db.prepare(`SELECT DISTINCT substr(${ym}, 1, 4) y FROM invoices ORDER BY y DESC`).all().map(r => r.y).filter(Boolean)
    const accName = Object.fromEntries(listAccounts().map(a => [a.id, accountLabel(a)]))
    const target = collecting(cfg)
    const here = req.originalUrl
    const money = (v, c) => v == null ? '–' : v.toLocaleString('de-DE', { minimumFractionDigits: 2, maximumFractionDigits: 2 }) + ' ' + (c && c !== 'EUR' ? c : '€')
    const ymd = (d) => /^\d{4}-\d{2}-\d{2}$/.test(d || '') ? `${d.slice(8, 10)}.${d.slice(5, 7)}.${d.slice(0, 4)}` : ''
    const statusOpts = [['open', `Offen (${(counts.open || 0) + (counts.error || 0)})`], ['sent', `In Lexware (${counts.sent || 0})`], ['private', `Privat (${counts.private || 0})`], ['order', `Auftragsbestätigungen (${counts.order || 0})`], ['nodoc', `Ohne Beleg (${counts.nodoc || 0})`], ['noinvoice', `Keine Rechnung (${counts.noinvoice || 0})`], ['duplicate', `Doppelt (${counts.duplicate || 0})`], ['blocked', `Gesperrt (${counts.blocked || 0})`], ['archived', `Jahr abgeschlossen (${counts.archived || 0})`], ['', 'Alle']]
    // nach Monat gruppieren (Monat = Rechnungsdatum)
    const ymOfRow = (r) => (/^\d{4}-\d{2}/.test(r.inv_date || '') ? r.inv_date : r.created_at).slice(0, 7)
    const groups = []
    for (const r of rows) { const k = ymOfRow(r); let g = groups[groups.length - 1]; if (!g || g.ym !== k) { g = { ym: k, rows: [] }; groups.push(g) } g.rows.push(r) }
    const isOpen = (r) => r.status === 'open' || r.status === 'error'
    const ready = (r) => isOpen(r) && r.file && r.suggestion !== 'check' && r.suggestion !== 'private'
    const sumOf = (list) => list.filter(r => r.amount != null && !['duplicate', 'noinvoice', 'nodoc', 'order'].includes(r.status)).reduce((a, r) => a + r.amount, 0)
    let idx = -1
    const rowHtml = (r) => { const i = ++idx; return `<tr class="ist-${esc(r.status)}" id="r${r.id}">
        <td><input type="checkbox" name="ids" value="${r.id}" form="ibulk" class="isel"></td>
        <td class="nowrap">${ymd(r.inv_date) || '<span class="muted">ohne Datum</span>'}</td>
        <td><div class="from">${esc(r.supplier || r.from_addr || '?')}${r.brand ? ` <span class="pill brand">${esc(r.brand)}</span>` : ''}</div>
          <div class="small muted">${r.number ? 'Nr. ' + esc(r.number) : 'ohne Nummer'}${r.einvoice ? ` <span class="pill info">${r.einvoice === 'xrechnung' ? 'XRechnung' : 'ZUGFeRD'}</span>` : ''}
          · ${r.source === 'scan' ? 'Scan' : esc(accName[r.account_id] || 'Mail')}
          ${r.risk ? ' · <span class="bad">Vorschau gesperrt</span>' : r.file ? ` · <a href="/rechnungen/${r.id}/datei" target="_blank" rel="noopener">${/\.xml$/i.test(r.file) ? 'XML' : 'PDF'} ansehen</a>` : ' · <span class="bad">kein Beleg</span>'}</div></td>
        <td><div class="what">${esc(r.content || r.subject || '–')}</div>
          ${r.status === 'blocked' ? `<div class="risk bad small">⚠ ${esc(r.hint || 'gesperrt')}</div>` : ''}
          ${isOpen(r) ? `<div class="small ${r.suggestion === 'check' ? 'check-text' : r.suggestion === 'private' ? 'warn-text' : 'muted'}">${r.suggestion === 'check' ? '❓ Bitte prüfen: Firma oder privat?' : r.suggestion === 'private' ? 'Vorschlag: privat' : 'Vorschlag: geschäftlich' + (r.brand ? ' (' + esc(r.brand) + ')' : '')}</div>`
            : `<div class="small muted">${esc(INV_STATUS[r.status] || r.status)}${r.decided_at ? ' · ' + fmtDate(r.decided_at) : ''}${r.hint && r.status === 'duplicate' ? ' · ' + esc(r.hint) : ''}</div>`}
          ${r.error ? `<div class="bad small">${esc(r.error)}</div>` : ''}
          <details><summary>Angaben ändern</summary><form method="post" action="/rechnungen/${r.id}/aendern" class="form two mini">${csrf(s)}<input type="hidden" name="anker" value="r${r.id}"><input type="hidden" name="zurueck" value="${esc(here)}">
            <label>Lieferant<input name="supplier" value="${esc(r.supplier)}" maxlength="120"></label>
            <label>Worum geht’s<input name="content" value="${esc(r.content || '')}" maxlength="120"></label>
            <label>Nummer<input name="number" value="${esc(r.number)}" maxlength="80"></label>
            <label>Rechnungsdatum<input name="inv_date" type="date" value="${esc(r.inv_date)}"></label>
            <label>Betrag brutto<input name="amount" value="${r.amount != null ? esc(String(r.amount).replace('.', ',')) : ''}" inputmode="decimal"></label>
            <label>Firma<select name="brand"><option value="">– keine / privat –</option>${options(companies.map(c => [c, c]), r.brand || '')}</select></label>
            <div class="row span"><button class="btn sm">Speichern</button></div></form></details></td>
        <td class="num nowrap"><b>${money(r.amount, r.currency)}</b></td>
        <td class="nowrap">${isOpen(r) ? `<form method="post" action="/rechnungen/aktion" class="inline">${csrf(s)}${anchor(rows, i, 'r')}<input type="hidden" name="zurueck" value="${esc(here)}"><input type="hidden" name="ids" value="${r.id}">
            <button class="btn sm primary" name="aktion" value="buchhaltung"${r.file ? '' : ' disabled'} data-confirm="${esc(`An Lexware senden?\n${r.supplier || r.from_addr} – ${r.content || ''} – ${money(r.amount, r.currency)}`)}">Ab zu Lexware</button>
            <button class="btn sm" name="aktion" value="privat">Privat</button>
            <button class="btn sm ghost" name="aktion" value="keine">Keine Rechnung</button>
            <button class="btn sm ghost" name="aktion" value="ab" title="In den Ordner für Auftragsbestätigungen – die KI lernt mit">Auftragsbestätigung</button></form>`
          : (r.status === 'private' || r.status === 'noinvoice' || r.status === 'order') ? `<form method="post" action="/rechnungen/aktion" class="inline">${csrf(s)}${anchor(rows, i, 'r')}<input type="hidden" name="zurueck" value="${esc(here)}"><input type="hidden" name="ids" value="${r.id}">
            <button class="btn sm ghost" name="aktion" value="oeffnen">Wieder öffnen</button></form>`
          : r.status === 'sent' ? '<span class="pill good">in Lexware</span>'
          : r.status === 'blocked' && r.file ? `<form method="post" action="/rechnungen/aktion" class="inline">${csrf(s)}${anchor(rows, i, 'r')}<input type="hidden" name="zurueck" value="${esc(here)}"><input type="hidden" name="ids" value="${r.id}">
            <button class="btn sm ghost" name="aktion" value="freigeben" data-confirm="Dieser Beleg wurde als gefährlich gesperrt. Nur freigeben, wenn du dir sicher bist, dass er echt ist. Die Vorschau bleibt gesperrt. Trotzdem freigeben?">Trotzdem freigeben</button></form>` : ''}</td>
      </tr>` }
    const monthHead = (g) => {
      const open = g.rows.filter(isOpen); const go = g.rows.filter(ready)
      const by = {}
      for (const r of g.rows.filter(r => r.amount != null && !['duplicate', 'noinvoice', 'blocked', 'nodoc', 'order'].includes(r.status))) {
        const k = r.status === 'private' || (isOpen(r) && r.suggestion === 'private') ? 'privat' : (isOpen(r) && r.suggestion === 'check') ? 'zu prüfen' : (r.brand || 'Firma')
        by[k] = (by[k] || 0) + r.amount
      }
      const list = go.map(r => `• ${r.supplier || r.from_addr}${r.content ? ' – ' + r.content : ''}: ${money(r.amount, r.currency)}`).join('\n')
      return `<div class="month-head">
        <div><h2>${esc(monthName(g.ym))} ${esc(g.ym.slice(0, 4))}</h2>
          <div class="muted small">${g.rows.length} Rechnung(en)${open.length && status !== 'open' ? `, ${open.length} offen` : ''} · <b>${money(sumOf(g.rows))}</b>${Object.keys(by).length > 1 ? ' · ' + Object.entries(by).map(([k, v]) => `${esc(k)} ${money(v)}`).join(' · ') : ''}</div></div>
        ${go.length ? `<form method="post" action="/rechnungen/aktion">${csrf(s)}<input type="hidden" name="zurueck" value="${esc(here)}">${go.map(r => `<input type="hidden" name="ids" value="${r.id}">`).join('')}
          <button class="btn primary" name="aktion" value="buchhaltung" data-confirm="${esc(`${go.length === 1 ? 'Diese geschäftliche Rechnung' : `Diese ${go.length} geschäftlichen Rechnungen`} aus ${monthName(g.ym)} ${g.ym.slice(0, 4)} an Lexware senden${go.length > 1 ? ` (zusammen ${money(sumOf(go))})` : ''}?\n\n${list}`)}">${go.length === 1 ? '1 geschäftliche' : go.length + ' geschäftliche'} ab zu Lexware</button></form>` : ''}
      </div>`
    }
    const body = `
    <h1>Rechnungen</h1>
    ${cfg.invoices.fromYear ? `<p class="muted small">Geprüft wird ab <b>${cfg.invoices.fromYear}</b> – ältere Jahre sind abgeschlossen (<a href="/einstellungen#rechnungen">ändern</a>).</p>` : ''}
    <p class="muted">Nichts geht von selbst zu Lexware – erst wenn du hier auf „Ab zu Lexware“ klickst. Zum Prüfen markierte (❓) und private Rechnungen werden beim Monats-Knopf nicht mitgeschickt.</p>
    ${target ? '' : '<div class="alert info">Noch kein Sammel-Postfach gewählt – <a href="/einstellungen#rechnungen">Einstellungen → Rechnungen</a>.</div>'}
    ${hasSecret('lexwareKey') ? '' : '<div class="alert info">Noch kein Lexware-Schlüssel hinterlegt – „Ab zu Lexware“ geht erst danach (<a href="/einstellungen#rechnungen">Einstellungen</a>).</div>'}
    <form method="get" action="/rechnungen" class="filters">
      <select name="status">${options(statusOpts, status)}</select>
      <select name="zuordnung"><option value="">Firma & privat</option>${options([...companies.map(c => [c, c]), ['privat', 'Privat'], ['pruefen', 'Bitte prüfen']], zu)}</select>
      <select name="jahr"><option value="">Alle Jahre</option>${options(years.map(y => [y, y]), jahr)}</select>
      <select name="monat"><option value="">Alle Monate</option>${options(Array.from({ length: 12 }, (_, i) => [String(i + 1).padStart(2, '0'), monthName('2000-' + String(i + 1).padStart(2, '0'))]), monat)}</select>
      <input name="q" value="${esc(q)}" placeholder="Lieferant, Inhalt, Nummer">
      <button class="btn">Filtern</button>
    </form>
    <p class="muted">${rows.length} Rechnungen · Summe ${money(sum)}${status === 'open' ? ' · Offene haben in Outlook ein Fähnchen.' : ''}</p>
    <form method="post" action="/rechnungen/aktion" id="ibulk">${csrf(s)}<input type="hidden" name="zurueck" value="${esc(here)}"></form>
    ${groups.map(g => `<section class="card month">${monthHead(g)}
      <div class="table-wrap"><table class="tbl invoices fixed"><colgroup><col class="c-sel"><col class="c-date"><col class="c-from"><col><col class="c-amt"><col class="c-act"></colgroup>
      <thead><tr><th><input type="checkbox" data-all="isel-${g.ym}" aria-label="Alle wählen"></th><th>Datum</th><th>Von</th><th>Worum geht’s</th><th class="num">Betrag</th><th></th></tr></thead>
      <tbody>${g.rows.map(rowHtml).join('').replace(/class="isel"/g, `class="isel isel-${g.ym}"`)}</tbody></table></div></section>`).join('') || `<section class="card"><p class="muted">${status === 'open' ? 'Keine offenen Rechnungen. 🎉' : 'Keine Rechnungen.'}</p></section>`}
    ${rows.length ? `<div class="row wrap">
      <button class="btn primary" form="ibulk" name="aktion" value="buchhaltung" data-confirm="Ausgewählte Rechnungen an Lexware Office senden?">Ausgewählte ab zu Lexware</button>
      <button class="btn" form="ibulk" name="aktion" value="privat">Ausgewählte privat</button>
      <button class="btn ghost" form="ibulk" name="aktion" value="keine">Ausgewählte: keine Rechnung</button>
      <button class="btn ghost" form="ibulk" name="aktion" value="ab">Ausgewählte: Auftragsbestätigung</button>
    </div>` : ''}`
    res.send(page({ title: 'Rechnungen', body, session: s, path: '/rechnungen', wide: true, ...flash(req) }))
  })

  const invBack = (v, a) => withAnchor((typeof v === 'string' && v.startsWith('/rechnungen') && !v.startsWith('//')) ? v.replace(/[?&](ok|fehler)=[^&]*/g, '') : '/rechnungen', a)
  app.post('/rechnungen/aktion', async (req, res) => {
    const ids = [].concat(req.body.ids || []).map(x => int(x, 1, 1e12, 0)).filter(Boolean).slice(0, 300)
    const to = invBack(req.body.zurueck, req.body.anker)
    if (!ids.length) return back(res, to, { err: 'Keine Rechnung ausgewählt.' })
    try {
      if (req.body.aktion === 'buchhaltung') {
        const r = await toAccounting(ids)
        return back(res, to, r.errors.length ? { err: `${r.done.length} gesendet, Fehler: ${r.errors.join(' | ')}` } : { msg: `${r.done.length} Rechnung(en) an Lexware Office gesendet – dort unter „Belege zu prüfen“.` })
      }
      if (req.body.aktion === 'privat') return back(res, to, { msg: `${await markPrivate(ids)} als privat abgelegt.` })
      if (req.body.aktion === 'ab') return back(res, to, { msg: `${await markOrder(ids)} als Auftragsbestätigung abgelegt.` })
      if (req.body.aktion === 'keine') return back(res, to, { msg: `${await markNoInvoice(ids)} als „keine Rechnung“ abgelegt.` })
      if (req.body.aktion === 'freigeben') return back(res, to, { msg: `${releaseInvoice(ids)} Beleg(e) freigegeben – jetzt „Zur Buchhaltung“ möglich.` })
      if (req.body.aktion === 'oeffnen') return back(res, to, { msg: `${await reopen(ids)} wieder offen.` })
      back(res, to, { err: 'Unbekannte Aktion.' })
    } catch (e) { back(res, to, { err: errText(e) }) }
  })
  app.post('/rechnungen/:id/aendern', async (req, res) => {
    try { await editInvoice(int(req.params.id, 1, 1e12, 0), req.body); back(res, invBack(req.body.zurueck, req.body.anker), { msg: 'Angaben gespeichert.' }) } catch (e) { back(res, invBack(req.body.zurueck, req.body.anker), { err: errText(e) }) }
  })
  app.get('/rechnungen/:id/datei', (req, res) => {
    const inv = getInvoice(int(req.params.id, 1, 1e12, 0))
    const p = inv && filePath(inv.file)
    if (!p || !fs.existsSync(p)) return res.status(404).send('Nicht gefunden')
    if (inv.risk) return res.status(403).send('Dieser Beleg wurde als gefährlich eingestuft – keine Vorschau.')
    const isXml = /\.xml$/i.test(p)
    res.set({ 'Content-Type': isXml ? 'text/plain; charset=utf-8' : 'application/pdf', 'Content-Security-Policy': "sandbox; default-src 'none'; style-src 'unsafe-inline'", 'Content-Disposition': `inline; filename*=UTF-8''${encodeURIComponent(inv.file_name || 'rechnung')}` })
    res.sendFile(p)
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
    const accounts = listAccounts()
    const target = collecting(cfg)
    const licSection = () => {
      const L = licenseState()
      if (L.exempt) return ''
      const label = { trial: 'Testzeitraum', active: 'Aktiv', trialover: 'Test abgelaufen', expired: 'Abgelaufen', lease: 'Nicht bestätigt', revoked: 'Gesperrt', invalid: 'Ungültig', nomodule: 'Modul fehlt', released: 'Freigegeben' }[L.state] || L.state
      return `<section class="card" id="lizenz"><h2>Lizenz</h2>
      <p>Status: <span class="pill ${L.state === 'active' ? 'good' : L.full ? 'warn' : 'bad'}">${esc(label)}</span>${L.license ? ` · ${esc(L.license.company)} · Schlüssel …${esc(L.license.keyHint)}${L.license.validUntil ? ' · gültig bis ' + esc(new Date(L.license.validUntil).toLocaleDateString('de-DE')) : ''}` : ''}</p>
      ${L.message ? `<p class="${L.full ? 'muted' : 'bad'}">${esc(L.message)}</p>` : ''}
      <p class="muted small">Postwart wird über die Vedly-Lizenz freigeschaltet (Modul „Postwart“). Ohne Lizenz läuft nach dem Test nur noch der Probelauf. Installations-ID: <code>${esc(L.installId)}</code></p>
      ${L.state === 'active' ? `<div class="row wrap"><form method="post" action="/lizenz/pruefen">${csrf(s)}<button class="btn">Jetzt bei der Zentrale prüfen</button></form>
        <form method="post" action="/lizenz/freigeben">${csrf(s)}<button class="btn ghost" data-confirm="Lizenz auf diesem Rechner freigeben (z. B. vor einem PC-Wechsel)? Danach nur noch Probelauf.">Lizenz freigeben</button></form></div>`
        : `<form method="post" action="/lizenz/aktivieren" class="form two">${csrf(s)}
        <label>Vedly-Lizenzschlüssel<input name="key" placeholder="VED-XXXX-XXXX-XXXX-XXXX" maxlength="40" autocomplete="off" required></label>
        <div class="row span"><button class="btn primary">Aktivieren</button></div></form>`}
      </section>`
    }
    const accountForm = (a) => `<form method="post" action="/postfaecher" class="form two">${csrf(s)}<input type="hidden" name="id" value="${a ? a.id : ''}">
        <label>Name (frei)<input name="name" value="${esc(a ? a.name : '')}" maxlength="80" placeholder="z. B. Info, Rechnung, Chef"></label>
        <label>Benutzer (meist die Mail-Adresse)<input name="user" value="${esc(a ? a.user : '')}" autocomplete="off" maxlength="200" required></label>
        <label>Server<input name="host" value="${esc(a ? a.host : (accounts[0] ? accounts[0].host : ''))}" placeholder="z. B. imap.dein-anbieter.de" maxlength="200" required></label>
        <label>Port<input name="port" type="number" value="${esc(a ? a.port : 993)}" min="1" max="65535"></label>
        <label>Passwort${a && accountHasPassword(a) ? ' <span class="pill good">gespeichert</span>' : ''}<input name="pass" type="password" autocomplete="new-password" placeholder="${a && accountHasPassword(a) ? 'leer lassen = unverändert' : ''}"${a ? '' : ' required'}></label>
        <label class="check"><input type="checkbox" name="secure" value="1"${chk(a ? a.secure : 1)}> SSL/TLS (Port 993)</label>
        <label class="check"><input type="checkbox" name="enabled" value="1"${chk(a ? a.enabled : 1)}> Sortieren eingeschaltet</label>
        <label class="check"><input type="checkbox" name="allowSelfSigned" value="1"${chk(a ? a.allow_self_signed : 0)}> Zertifikat nicht prüfen (nur wenn nötig)</label>
        <div class="row span"><button class="btn primary" name="next" value="save">${a ? 'Speichern' : 'Hinzufügen'}</button><button class="btn" name="next" value="test">${a ? 'Speichern' : 'Hinzufügen'} &amp; testen</button></div>
      </form>`
    const smtpForm = (a) => { const c = smtpOf(a); return `<h3>Postausgang (zum Schreiben im Webmail)</h3>
      <form method="post" action="/postfaecher/${a.id}/postausgang" class="form two">${csrf(s)}
        <label>Postausgangsserver (SMTP)<input name="host" value="${esc(a.smtp_host || '')}" placeholder="${esc(c.host)}" maxlength="200"></label>
        <label>Port<input name="port" type="number" value="${esc(c.port)}" min="1" max="65535"></label>
        <label class="check"><input type="checkbox" name="secure" value="1"${chk(c.secure)}> SSL/TLS (Port 465) – aus = STARTTLS (Port 587)</label>
        <label>Absendername (z. B. „Michael Zatti – Flexisticker“)<input name="fromName" value="${esc(a.from_name || '')}" maxlength="80"></label>
        <label>Benutzer (leer = wie oben)<input name="user" value="${esc(a.smtp_user || '')}" placeholder="${esc(a.user)}" maxlength="200" autocomplete="off"></label>
        <label class="check"><input type="checkbox" name="same" value="1"${chk(a.smtp_same !== 0)}> Gleiches Passwort wie beim Empfang</label>
        <label>Eigenes Passwort für den Postausgang${a.smtp_same === 0 && getSecret('smtp:' + a.id) ? ' <span class="pill good">gespeichert</span>' : ''}<input name="pass" type="password" autocomplete="new-password" placeholder="nur nötig, wenn anders als beim Empfang"></label>
        <div class="row span"><button class="btn" name="next" value="save">Speichern</button><button class="btn" name="next" value="test">Speichern &amp; testen</button></div>
      </form>` }
    const body = `
    <h1>Einstellungen</h1>
    <div class="set-wrap"><nav class="set-nav" aria-label="Bereiche der Einstellungen">
      ${[['betrieb', 'allgemein', 'Allgemein'], ['postfaecher', 'postfaecher', 'Postfächer'], ['sortieren', 'sortieren', 'Sortieren'], ['ordner', 'ordner', 'Ordner'],
        ...(s.features.invoices ? [['rechnungen', 'rechnungen', 'Rechnungen']] : []), ['sicherheit', 'sicherheit', 'Sicherheit'], ['konto', 'konto', 'Mein Konto']]
        .map(([id, g, l]) => `<a href="#${id}" data-tab="${g}">${l}</a>`).join('')}
    </nav><div class="set-body">
    <section class="card" id="betrieb" data-group="allgemein"><h2>Dein Betrieb</h2>
      <p class="muted">Hilft der KI beim Einordnen und bei der Frage „Firma oder privat?“. Nichts davon verlässt deinen Rechner.</p>
      <form method="post" action="/einstellungen/betrieb" class="form two">${csrf(s)}
        <label>Name des Betriebs<input name="bizName" value="${esc(cfg.business.name)}" maxlength="80" placeholder="z. B. Musterdruck"></label>
        <label>Was macht der Betrieb?<input name="bizDesc" value="${esc(cfg.business.description)}" maxlength="200" placeholder="z. B. Textildruck und Werbetechnik"></label>
        <label>Dein Name, wie er auf Rechnungen steht<input name="ownerName" value="${esc(cfg.invoices.ownerName)}" maxlength="80" placeholder="z. B. Max Muster"></label>
        <label>Deine Firmen/Marken (je Zeile)<textarea name="companies" rows="3" maxlength="500" placeholder="z. B. Musterdruck">${esc(cfg.invoices.companies)}</textarea></label>
        <p class="muted small span">Steht eine dieser Firmen in einer Rechnung (z. B. „Max Muster – Musterdruck“), gilt sie als geschäftlich und bekommt das Etikett der Firma. Steht nur dein Name da, entscheidet die KI nach dem Inhalt – im Zweifel „Bitte prüfen“.</p>
        <div class="row span"><button class="btn primary">Speichern</button></div>
      </form></section>

    ${s.admin ? licSection() : ''}

    <section class="card" id="postfaecher" data-group="postfaecher"><h2>Postfächer</h2>
      <p class="muted">Alle Postfächer, die sortiert werden sollen (Zugangsdaten wie in Outlook). Passwörter werden verschlüsselt gespeichert und nie angezeigt. Gelerntes gilt für alle Postfächer.</p>
      ${accounts.map(a => `<details class="acc"${String(req.query.offen) === String(a.id) ? ' open' : ''}><summary><b>${esc(accountLabel(a))}</b> <span class="muted small">${esc(a.user)} · ${esc(a.host)}</span>
          <span class="pill ${a.mode === 'live' ? 'good' : 'warn'}">${a.mode === 'live' ? 'Scharf' : 'Probelauf'}</span>${a.enabled ? '' : ' <span class="pill">aus</span>'}${target && target.id === a.id ? ' <span class="pill info">Rechnungen</span>' : ''}</summary>
        <form method="post" action="/aktion/modus" class="row wrap mode-row">${csrf(s)}<input type="hidden" name="account" value="${a.id}"><input type="hidden" name="zurueck" value="einstellungen">
          ${a.mode === 'live'
            ? '<span class="muted small">Sortieren ist scharf: Mails werden wirklich verschoben.</span><input type="hidden" name="mode" value="probe"><button class="btn sm">Zurück in den Probelauf</button>'
            : `<span class="muted small">Probelauf: Postwart zeigt nur, wo es einsortieren würde.</span><input type="hidden" name="mode" value="live"><button class="btn sm primary" data-confirm="${esc(accountLabel(a))} scharf schalten? Mails werden dann wirklich in die Ordner verschoben (gelöscht wird nichts).">Sortieren scharf schalten</button>`}</form>
        ${accountForm(a)}
        ${s.features.webmail ? smtpForm(a) : ''}
        <form method="post" action="/postfaecher/${a.id}/loeschen" class="row">${csrf(s)}<button class="btn ghost sm" data-confirm="${esc(accountLabel(a))} aus Postwart entfernen? Im Postfach selbst bleibt alles, wie es ist.">Postfach entfernen</button></form>
      </details>`).join('')}
      <details class="acc"${accounts.length ? '' : ' open'}><summary><b>+ Postfach hinzufügen</b></summary>${accountForm(null)}</details>
    </section>

    ${!s.features.invoices ? '' : `<section class="card" id="rechnungen" data-group="rechnungen"><h2>Rechnungen</h2>
      ${Number(cfg.invoices.accountId) > 0 ? '' : '<div class="alert info">Rechnungen werden noch nicht gesammelt. Der Reiter „Rechnungen“ oben erscheint, sobald du hier ein Sammel-Postfach wählst – wer das nicht braucht, sieht ihn nicht.</div>'}
      <p class="muted">Rechnungen aus allen Postfächern werden im Sammel-Postfach nach Jahr und Monat abgelegt (z. B. „${esc(cfg.invoices.root)}/2026/2026-11“). Aus anderen Postfächern kommt eine Kopie, das Original wandert dort nach „Sortiert/Rechnungen“. Offene Rechnungen bekommen in Outlook ein Fähnchen.</p>
      <form method="post" action="/einstellungen/rechnungen" class="form two">${csrf(s)}
        <label>Sammel-Postfach<select name="accountId"><option value="0">– Rechnungen nicht sammeln –</option>${options(accounts.map(a => [a.id, accountLabel(a) + ' (' + a.user + ')']), cfg.invoices.accountId)}</select></label>
        <label>Hauptordner<input name="root" value="${esc(cfg.invoices.root)}" maxlength="60"></label>
        <label>Ordner für Privates<input name="privateName" value="${esc(cfg.invoices.privateName)}" maxlength="60"></label>
        <label>Ordner für „keine Rechnung“<input name="noInvoiceName" value="${esc(cfg.invoices.noInvoiceName)}" maxlength="60"></label>
        <label>Ordner für Auftragsbestätigungen<input name="orderName" value="${esc(cfg.invoices.orderName || 'Auftragsbestätigungen')}" maxlength="60"></label>
        <label class="check span"><input type="checkbox" name="flagOpen" value="1"${chk(cfg.invoices.flagOpen)}> Offene Rechnungen in Outlook mit Fähnchen markieren</label>
        <label>Zu Lexware prüfen ab Jahr<input name="fromYear" type="number" min="0" max="2100" value="${cfg.invoices.fromYear || ''}" placeholder="alle Jahre"></label>
        <p class="muted small">Ältere Jahre sind erledigt: Rechnungen daraus werden weiter nach Jahr/Monat abgelegt, aber ohne Fähnchen und ohne „Ab zu Lexware“ (Status „Jahr abgeschlossen“).</p>
        ${!s.features.scan ? '' : `<label class="check"><input type="checkbox" name="scanEnabled" value="1"${chk(cfg.invoices.scanEnabled)}> Scanner-Ordner abholen</label>
        ${PLATFORM === 'windows' ? `<label>Scanner-Ordner<input name="scanDir" value="${esc(cfg.invoices.scanDir)}" maxlength="260" placeholder="z. B. C:\\Scans oder \\\\NAS\\scan"></label>
        <label>Benutzer für die Netzwerkfreigabe (nur bei \\\\…)<input name="scanUser" value="${esc(cfg.invoices.scanUser)}" maxlength="120" autocomplete="off"></label>
        <label>Passwort der Freigabe${hasSecret('scanPassword') ? ' <span class="pill good">gespeichert</span>' : ''}<input name="scanPass" type="password" autocomplete="new-password" placeholder="${hasSecret('scanPassword') ? 'leer lassen = unverändert' : ''}"></label>
        <p class="muted small span">Den Ordner, in den dein Scanner die PDFs legt (gleicher Pfad wie im Explorer). Postwart läuft als Windows-Dienst: Laufwerksbuchstaben wie <code>S:</code> sieht er nicht – für Netzwerkordner den vollen Pfad <code>\\\\Server\\Freigabe</code> mit Benutzer und Passwort angeben. Verarbeitete Dateien wandern nach <code>erledigt\\JJJJ-MM</code> – gelöscht wird nichts.</p>`
          : `<label>Scanner-Ordner (im Container)<input name="scanDir" value="${esc(cfg.invoices.scanDir)}" maxlength="200"></label>
        <p class="muted small span">Der Scanner legt PDFs in eine Freigabe, die beim Container als <code>/scan</code> eingebunden ist. Verarbeitete Dateien wandern nach <code>erledigt/JJJJ-MM</code>, doppelte nach <code>erledigt/doppelt</code> – gelöscht wird nichts. Scans werden nur abgeholt, wenn das Sammel-Postfach scharf ist.</p>`}
        <div class="row span"><button class="btn" name="next" value="scantest">Speichern &amp; Ordner prüfen</button></div>`}
        ${!s.features.lexware ? '' : `<label>Lexware-API-Schlüssel${hasSecret('lexwareKey') ? ' <span class="pill good">gespeichert</span>' : ''}<input name="lexwareKey" type="password" autocomplete="new-password" placeholder="${hasSecret('lexwareKey') ? 'leer lassen = unverändert' : 'Schlüssel aus Lexware Office'}"></label>
        <label>Lexware-Adresse<input name="lexwareUrl" value="${esc(cfg.invoices.lexwareUrl)}" maxlength="200"></label>
        <p class="muted small span">Eigenen Schlüssel anlegen (Lexware Office → Erweiterungen → Public API) mit möglichst wenigen Rechten: <b>Dateien/Belegbilder hochladen</b> und <b>Profil lesen</b>. „Zur Buchhaltung“ legt die Rechnung in Lexware unter „Belege zu prüfen“ ab.</p>`}
        <div class="row span"><button class="btn primary" name="next" value="save">Speichern</button>${s.features.lexware ? '<button class="btn" name="next" value="test">Speichern &amp; Lexware testen</button>' : ''}</div>
      </form></section>`}


    <section class="card" id="sortieren" data-group="sortieren"><h2>Sortieren</h2>
      <form method="post" action="/einstellungen/sortieren" class="form">${csrf(s)}
        <label class="check"><input type="checkbox" name="onlySeen" value="1"${chk(cfg.sorting.onlySeen)}> <span><b>Nur gelesene Mails einsortieren</b> – ungelesene bleiben im Posteingang, bis du sie gelesen hast. Auf Gefahr geprüft werden sie trotzdem sofort.</span></label>
        <p class="muted small">Gefährliche Mails (Phishing, Betrug, gefährliche Anhänge):</p>
        <label class="check"><input type="radio" name="danger" value="mark"${cfg.sorting.danger === 'mark' ? ' checked' : ''}> <span><b>Nur markieren</b> – bleiben im Posteingang, bekommen ein Fähnchen und das Schlagwort „Phishing“. Nichts verschwindet.</span></label>
        <label class="check"><input type="radio" name="danger" value="move"${cfg.sorting.danger !== 'mark' ? ' checked' : ''}> <span><b>Markieren und verschieben</b> nach „${esc(targetLabel('verdacht', cfg))}“.</span></label>
        <div class="row"><button class="btn primary">Speichern</button></div>
      </form></section>

    ${s.features.webmail ? `<section class="card" id="mailprogramm" data-group="postfaecher"><h2>Mail-Programm</h2>
      <form method="post" action="/einstellungen/mailprogramm" class="form two">${csrf(s)}
        <label>Am Handy und Tablet nur die Mails der letzten … Tage zeigen<input name="mobileDays" type="number" value="${int(cfg.webmail?.mobileDays, 0, 3650, 14)}" min="0" max="3650"></label>
        <p class="muted small">0 = alle. Ältere Mails bleiben auf dem Server und lassen sich jederzeit mit „Ältere anzeigen“ oder über die Suche öffnen. Postwart speichert keine Mails auf dem Gerät – es lädt nur die angezeigte Liste und die Mail, die du öffnest.</p>
        <div class="row span"><button class="btn primary">Speichern</button></div>
      </form></section>` : ''}

    <section class="card" id="ablauf" data-group="sortieren"><h2>Ablauf</h2>
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

    ${!s.features.folders ? `<section class="card" id="ordner" data-group="ordner"><h2>Ordner</h2><p class="muted">Die Mails werden in diese Ordner unter „${esc(cfg.root)}“ sortiert. Ändern kann sie der Verwalter.</p>
      <ul>${activeCategories(cfg).map(c => `<li><b>${esc(c.name)}</b> <span class="muted small">${esc(c.desc)}</span></li>`).join('')}</ul></section>` : `<section class="card" id="ordner" data-group="ordner"><h2>Ordner</h2>
      <p class="muted">Die Ordner liegen unter „${esc(cfg.root)}“ in jedem Postfach und erscheinen in Outlook. Die Beschreibung ist das, was die KI über den Ordner weiß – je genauer, desto besser. Wird ein Name geändert, legt Postwart einen neuen Ordner an; der alte bleibt (in Outlook umbenennen oder löschen).</p>
      <form method="post" action="/einstellungen/ordner" class="form">${csrf(s)}
        <label>Hauptordner<input name="root" value="${esc(cfg.root)}" maxlength="60" required></label>
        ${cfg.categories.map(c => `<details class="cat"><summary><b>${esc(c.name)}</b>${c.custom ? ' <span class="pill">eigener Ordner</span>' : ''}${c.system ? ' <span class="pill warn">Sicherheit</span>' : ''}${c.off ? ' <span class="pill">nicht verwendet</span>' : ''}<span class="cat-desc muted small">${esc(c.desc)}</span></summary>
          <label>Name<input name="name_${c.id}" value="${esc(c.name)}" maxlength="60" required></label>
          ${c.system ? `<p class="muted small">${esc(c.desc)} Diesen Ordner füllt nur die Sicherheitsprüfung (Einstellungen → Sicherheit), nie die KI.</p>`
            : `<label>Beschreibung für die KI – was gehört hier rein?<textarea name="desc_${c.id}" rows="2" maxlength="600">${esc(c.desc)}</textarea></label>
          <div class="row wrap"><label class="check"><input type="checkbox" name="off_${c.id}" value="1"${chk(c.off)}> nicht verwenden</label>
          ${c.custom ? `<label class="check"><input type="checkbox" name="del_${c.id}" value="1"> Ordner entfernen</label>` : ''}</div>`}</details>`).join('')}
        <div class="row"><button class="btn primary">Speichern</button><button class="btn ghost" name="reset" value="1" data-confirm="Namen und Beschreibungen der festen Ordner auf die Vorgaben zurücksetzen? Eigene Ordner bleiben.">Vorgaben</button></div>
      </form>
      <h3>Eigenen Ordner anlegen</h3>
      <form method="post" action="/einstellungen/ordner/neu" class="form two">${csrf(s)}
        <label>Name<input name="name" maxlength="60" required placeholder="z. B. Ausmisten – Gewinnspiele"></label>
        <label class="span">Was gehört hier rein? (für die KI)<textarea name="desc" rows="2" maxlength="600" required placeholder="z. B. Gewinnspiele, Verlosungen, „Sie haben gewonnen“-Mails"></textarea></label>
        <div class="row span"><button class="btn primary">Anlegen</button></div>
      </form></section>`}

    <section class="card" id="sicherheit" data-group="sicherheit"><h2>Sicherheit</h2>
      <p class="muted">Jede Mail wird vor allem anderen geprüft: gefährliche Anhänge (Programme, Makros, getarnte Dateien, Archive mit Passwort), PDFs mit Skripten, gefälschte Absender und Links, nachgemachte Domains, Druck plus Passwortabfrage, Absender-Prüfung des Mailservers (SPF/DKIM/DMARC). Anhänge werden dabei nie geöffnet. Verdächtige Mails kommen nach „${esc(targetLabel('verdacht', cfg))}“, Spam nach „${esc(targetLabel('spam', cfg))}“ – gelöscht wird nichts.</p>
      ${getStatus().dnsWarning ? `<div class="alert bad">Spam-Sperrliste: ${esc(getStatus().dnsWarning)}. Abhilfe: unten einen anderen DNS-Server eintragen und „Speichern &amp; Sperrlisten testen“ – oder die Liste entfernen.</div>` : ''}
      <form method="post" action="/einstellungen/sicherheit" class="form two">${csrf(s)}
        <label>Ab dieser Punktzahl „Verdacht“<input name="phishThreshold" type="number" value="${cfg.security.phishThreshold}" min="20" max="300"></label>
        <label>Ab dieser Punktzahl Warnhinweis<input name="warnThreshold" type="number" value="${cfg.security.warnThreshold}" min="5" max="300"></label>
        <label class="check span"><input type="checkbox" name="blockDangerous" value="1"${chk(cfg.security.blockDangerous)}> Mails mit gefährlichen Anhängen immer nach „Verdacht“ (empfohlen)</label>
        <label class="check span"><input type="checkbox" name="spamHeader" value="1"${chk(cfg.security.spamHeader)}> Spam-Kennzeichnung des Mailservers übernehmen (X-Spam-Flag deines Anbieters)</label>
        <label class="check span"><input type="checkbox" name="dnsbl" value="1"${chk(cfg.security.dnsbl)}> <span>Spam-Sperrlisten abfragen – dabei gehen <b>nur IP-Adresse des Absender-Servers und Domains</b> an den Listenbetreiber, nie Inhalte</span></label>
        <label>Sperrlisten für Server-IPs (je Zeile)<textarea name="ipLists" rows="2" maxlength="300">${esc(cfg.security.ipLists)}</textarea></label>
        <label>Sperrlisten für Domains (je Zeile)<textarea name="domainLists" rows="2" maxlength="300">${esc(cfg.security.domainLists)}</textarea></label>
        <label>DNS-Server für die Sperrlisten (leer = automatisch)<input name="dnsServer" maxlength="120" value="${esc(cfg.security.dnsServer || '')}" placeholder="z. B. 192.168.1.1"></label>
        <p class="muted small">Automatisch nutzt er gerade: ${esc(systemDnsServers().join(', ') || '–')}. Spamhaus sperrt öffentliche DNS-Server (Google, Cloudflare, oft auch die der Internetanbieter). Funktioniert nur mit einem DNS-Server, der selbst auflöst (z. B. Pi-hole mit Unbound) – der Test zeigt es.</p>
        <label class="span">Weitere oft gefälschte Absender (je Zeile „Name = domain.de, domain2.de“)<textarea name="brands" rows="2" maxlength="2000" placeholder="Meine Bank = meinebank.de">${esc(cfg.security.brands)}</textarea></label>
        <p class="muted small span">Spamhaus und SURBL sind für kleine Mengen kostenlos. Fehlalarm? In der Mailliste „ist harmlos“ klicken oder die Mail in Outlook aus dem Ordner ziehen – der Absender gilt dann als vertrauenswürdig.</p>
        <div class="row span"><button class="btn primary">Speichern</button><button class="btn" name="next" value="test">Speichern &amp; Sperrlisten testen</button></div>
      </form>
      ${!s.features.cleanup ? '' : (() => { const cc = cleanupCfg(cfg); return `<h3 id="aufraeumen">Spam und Verdacht aufräumen</h3>
      <p class="muted">Standard: nie. Gezählt wird ab dem Tag, an dem die Mail im Ordner liegt – du hast also immer die volle Frist zum Nachsehen. Mails mit Fähnchen bleiben. Gilt nur für scharf geschaltete Postfächer.</p>
      <form method="post" action="/einstellungen/aufraeumen" class="form two">${csrf(s)}
        <label>„${esc(targetLabel('spam', cfg))}“ aufräumen nach … Tagen (0 = nie)<input name="spam" type="number" min="0" max="3650" value="${cc.spam}"></label>
        <label>„${esc(targetLabel('verdacht', cfg))}“ aufräumen nach … Tagen (0 = nie)<input name="verdacht" type="number" min="0" max="3650" value="${cc.verdacht}"></label>
        <label class="check span"><input type="radio" name="mode" value="trash"${cc.mode === 'trash' ? ' checked' : ''}> <span>In den Papierkorb des Postfachs legen (empfohlen – dort noch wiederherstellbar)</span></label>
        <label class="check span"><input type="radio" name="mode" value="delete"${cc.mode === 'delete' ? ' checked' : ''}> <span>Endgültig löschen (nicht wiederherstellbar)</span></label>
        <div class="row span"><button class="btn primary">Speichern</button>
          <button class="btn" name="leeren" value="spam" data-confirm="Alle Mails im Ordner „${esc(targetLabel('spam', cfg))}“ (ohne Fähnchen) in allen scharf geschalteten Postfächern jetzt ${cc.mode === 'delete' ? 'ENDGÜLTIG LÖSCHEN' : 'in den Papierkorb legen'}?">„${esc(targetLabel('spam', cfg))}“ jetzt leeren</button>
          <button class="btn" name="leeren" value="verdacht" data-confirm="Alle Mails im Ordner „${esc(targetLabel('verdacht', cfg))}“ (ohne Fähnchen) in allen scharf geschalteten Postfächern jetzt ${cc.mode === 'delete' ? 'ENDGÜLTIG LÖSCHEN' : 'in den Papierkorb legen'}?">„${esc(targetLabel('verdacht', cfg))}“ jetzt leeren</button></div>
      </form>` })()}</section>

    <section class="card" id="konto" data-group="konto"><h2>Konto</h2>
      <p>Angemeldet als <b>${esc(s.display)}</b> (${esc(s.name)})${s.admin ? ' · Verwalter' : ''}.</p>
      <h3>Passwort ändern</h3>
      <form method="post" action="/einstellungen/passwort" class="form two">${csrf(s)}
        <input type="text" name="username" value="${esc(s.name)}" autocomplete="username" hidden>
        <label>Aktuelles Passwort<input name="old" type="password" required autocomplete="current-password"></label>
        <label>Neues Passwort (mind. 10 Zeichen)<input name="pw" type="password" required minlength="10" autocomplete="new-password"></label>
        <div class="row span"><button class="btn">Passwort ändern</button></div>
        <p class="muted small span">Alle anderen Geräte werden dabei abgemeldet, dieses bleibt angemeldet.</p>
      </form>
      <h3>Zwei-Faktor-Anmeldung</h3>
      <p><span class="pill good">aktiv</span> Noch <b>${recoveryLeft(s.userId)}</b> von 10 Notfallcodes übrig.</p>
      <form method="post" action="/einstellungen/notfallcodes" class="row wrap">${csrf(s)}
        <input name="code" inputmode="numeric" maxlength="20" required placeholder="Code aus der App" autocomplete="one-time-code">
        <button class="btn" data-confirm="Neue Notfallcodes erzeugen? Die alten gelten dann nicht mehr.">Neue Notfallcodes erzeugen</button></form>
      <p class="muted small">Neues Handy? Bitte den Verwalter, deine Zwei-Faktor-Anmeldung zurückzusetzen – dann richtest du die App bei der nächsten Anmeldung neu ein.</p>
      <form method="post" action="/abmelden">${csrf(s)}<button class="btn ghost">Abmelden</button></form></section></div></div>`
    res.send(page({ title: 'Einstellungen', body, session: s, path: '/einstellungen', wide: true, ...flash(req) }))
  })

  app.post('/postfaecher', async (req, res) => {
    const b = req.body
    let acc
    try {
      acc = saveAccount({ id: b.id, name: b.name, host: b.host, port: b.port, user: b.user, secure: b.secure === '1', allowSelfSigned: b.allowSelfSigned === '1', enabled: b.enabled === '1' }, b.pass)
    } catch (e) { return back(res, '/einstellungen#postfaecher', { err: errText(e) }) }
    const to = `/einstellungen?offen=${acc.id}#postfaecher`
    if (b.next !== 'test') return back(res, to, { msg: `${accountLabel(acc)} gespeichert.` })
    try {
      const info = await withClient(acc, async (client) => {
        const folders = await listFolders(client)
        const st = await client.status('INBOX', { messages: true, unseen: true })
        return { folders, st, ns: client.namespace }
      })
      log('info', `${accountLabel(acc)}: Test ok, ${info.st.messages} Mails im Posteingang`)
      back(res, to, { msg: `${accountLabel(acc)}: Verbindung klappt – ${info.st.messages} Mails im Posteingang (${info.st.unseen} ungelesen), ${info.folders.length} Ordner. Es läuft im Probelauf, bis du es in der Übersicht scharf schaltest.` })
    } catch (e) {
      back(res, to, { err: `${accountLabel(acc)}: Test fehlgeschlagen – ` + (e.authenticationFailed ? 'Benutzer oder Passwort falsch.' : errText(e)) })
    }
  })
  app.post('/postfaecher/:id/postausgang', async (req, res) => {
    const b = req.body
    const a = getAccount(req.params.id)
    if (!a) return back(res, '/einstellungen#postfaecher', { err: 'Nicht gefunden.' })
    const to = `/einstellungen?offen=${a.id}#postfaecher`
    let acc
    try { acc = saveSmtp(a.id, { host: b.host, port: b.port, secure: b.secure === '1', user: b.user, same: b.same === '1', fromName: b.fromName }, b.pass) } catch (e) { return back(res, to, { err: errText(e) }) }
    if (b.next !== 'test') return back(res, to, { msg: 'Postausgang gespeichert.' })
    try { await testSmtp(acc); back(res, to, { msg: `Postausgang klappt (${smtpOf(acc).host}).` }) } catch (e) { back(res, to, { err: 'Postausgang-Test fehlgeschlagen: ' + (e.code === 'EAUTH' ? 'Benutzer oder Passwort falsch.' : errText(e)) }) }
  })
  app.post('/postfaecher/:id/loeschen', (req, res) => {
    const acc = getAccount(req.params.id)
    if (!acc) return back(res, '/einstellungen#postfaecher', { err: 'Nicht gefunden.' })
    deleteAccount(acc.id)
    if (getConfig().invoices.accountId === acc.id) saveConfig({ invoices: { accountId: 0 } })
    log('info', `Postfach ${accountLabel(acc)} entfernt`)
    back(res, '/einstellungen#postfaecher', { msg: `${accountLabel(acc)} entfernt.` })
  })

  app.post('/einstellungen/betrieb', (req, res) => {
    const b = req.body
    saveConfig({
      business: { name: String(b.bizName || '').trim().slice(0, 80), description: String(b.bizDesc || '').trim().slice(0, 200) },
      invoices: { ownerName: String(b.ownerName || '').trim().slice(0, 80), companies: String(b.companies || '').split(/\r?\n/).map(x => x.trim()).filter(Boolean).slice(0, 20).join('\n') }
    })
    back(res, '/einstellungen#betrieb', { msg: 'Gespeichert.' })
  })
  app.post('/lizenz/aktivieren', async (req, res) => {
    try { await activate(req.body.key, getConfig().business.name || ('Postwart ' + os.hostname())); back(res, '/einstellungen#lizenz', { msg: 'Lizenz aktiviert – vielen Dank!' }) } catch (e) { back(res, '/einstellungen#lizenz', { err: errText(e) }) }
  })
  app.post('/lizenz/pruefen', async (req, res) => {
    const st = await checkin({ force: true })
    back(res, '/einstellungen#lizenz', st.check && st.check.ok ? { msg: 'Lizenz bestätigt.' } : { err: 'Prüfung fehlgeschlagen: ' + ((st.check && st.check.error) || 'unbekannt') })
  })
  app.post('/lizenz/freigeben', async (req, res) => {
    try { await release(); back(res, '/einstellungen#lizenz', { msg: 'Lizenz freigegeben – sie kann jetzt auf einem anderen Rechner aktiviert werden.' }) } catch (e) { back(res, '/einstellungen#lizenz', { err: errText(e) }) }
  })

  app.post('/einstellungen/rechnungen', async (req, res) => {
    const b = req.body
    const accId = int(b.accountId, 0, 1e9, 0)
    if (accId && !getAccount(accId)) return back(res, '/einstellungen#rechnungen', { err: 'Postfach nicht gefunden.' })
    const lexUrl = String(b.lexwareUrl || '').trim()
    if (lexUrl && !/^https:\/\//.test(lexUrl) && !/^http:\/\/(127\.0\.0\.1|localhost)(:|\/|$)/.test(lexUrl)) return back(res, '/einstellungen#rechnungen', { err: 'Lexware-Adresse muss mit https:// beginnen.' })
    saveConfig({ invoices: {
      accountId: accId,
      root: cleanFolderName(b.root) || 'Rechnungen',
      privateName: cleanFolderName(b.privateName) || 'Privat',
      noInvoiceName: cleanFolderName(b.noInvoiceName) || 'Keine Rechnung',
      orderName: cleanFolderName(b.orderName) || 'Auftragsbestätigungen',
      flagOpen: b.flagOpen === '1',
      scanEnabled: b.scanEnabled === '1',
      fromYear: b.fromYear ? int(b.fromYear, 2000, 2100, 0) : 0,
      scanDir: String(b.scanDir || '').trim().slice(0, 260),
      scanUser: String(b.scanUser || '').trim().slice(0, 120),
      lexwareUrl: lexUrl || 'https://api.lexware.io',
    } })
    if (b.lexwareKey) setSecret('lexwareKey', String(b.lexwareKey).trim().slice(0, 500))
    if (b.scanPass) setSecret('scanPassword', String(b.scanPass).slice(0, 200))
    if (b.next === 'scantest') {
      try { const r = await checkScanDir(); return back(res, '/einstellungen#rechnungen', { msg: `Scanner-Ordner erreichbar: ${r.pdfs} PDF(s) warten, Schreiben klappt.` }) } catch (e) { return back(res, '/einstellungen#rechnungen', { err: 'Scanner-Ordner: ' + errText(e) }) }
    }
    const yr = await applyYearSetting().catch(e => { log('warn', e.message); return { closed: 0, opened: 0 } })
    if (b.next !== 'test' && (yr.closed || yr.opened)) return back(res, '/einstellungen#rechnungen', { msg: `Gespeichert. ${yr.closed ? yr.closed + ' Rechnung(en) älterer Jahre abgeschlossen' : ''}${yr.closed && yr.opened ? ', ' : ''}${yr.opened ? yr.opened + ' wieder offen' : ''}.` })
    if (b.next !== 'test') return back(res, '/einstellungen#rechnungen', { msg: 'Gespeichert.' })
    try { const name = await lexwareTest(); back(res, '/einstellungen#rechnungen', { msg: `Lexware Office verbunden: ${name}` }) } catch (e) { back(res, '/einstellungen#rechnungen', { err: 'Lexware-Test fehlgeschlagen: ' + errText(e) }) }
  })

  app.post('/einstellungen/ki', (req, res) => res.redirect(303, '/verwaltung/ki'))

  app.post('/einstellungen/mailprogramm', (req, res) => {
    saveConfig({ webmail: { mobileDays: int(req.body.mobileDays, 0, 3650, 14) } })
    back(res, '/einstellungen#mailprogramm', { msg: 'Gespeichert.' })
  })
  app.post('/einstellungen/sortieren', (req, res) => {
    saveConfig({ sorting: { onlySeen: req.body.onlySeen === '1', danger: req.body.danger === 'mark' ? 'mark' : 'move' } })
    log('info', `Sortieren: ${req.body.onlySeen === '1' ? 'nur gelesene Mails' : 'alle Mails'}, gefährliche Mails ${req.body.danger === 'mark' ? 'nur markieren' : 'verschieben'}`)
    back(res, '/einstellungen#sortieren', { msg: 'Gespeichert.' })
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
    const cfg = getConfig()
    if (b.reset === '1') {
      saveConfig({ categories: cfg.categories.filter(c => c.custom) })
      return back(res, '/einstellungen#ordner', { msg: 'Vorgaben wiederhergestellt.' })
    }
    const root = cleanFolderName(b.root) || 'Sortiert'
    const cats = cfg.categories.filter(c => !(c.custom && b['del_' + c.id] === '1')).map(c => ({
      id: c.id, name: cleanFolderName(b['name_' + c.id]) || c.name,
      desc: c.system ? c.desc : String(b['desc_' + c.id] ?? c.desc).slice(0, 600),
      off: c.system ? false : b['off_' + c.id] === '1'
    }))
    const names = cats.map(c => c.name.toLowerCase())
    if (new Set(names).size !== names.length) return back(res, '/einstellungen#ordner', { err: 'Zwei Ordner haben denselben Namen.' })
    const removed = cfg.categories.filter(c => c.custom && b['del_' + c.id] === '1')
    for (const c of removed) db.prepare("DELETE FROM rules WHERE target = ? AND kind IN ('sender', 'domain')").run(c.id)
    saveConfig({ root, categories: cats })
    back(res, '/einstellungen#ordner', { msg: removed.length ? `Gespeichert, ${removed.length} Ordner entfernt (im Postfach bleibt er bestehen).` : 'Gespeichert.' })
  })
  app.post('/einstellungen/ordner/neu', (req, res) => {
    const cfg = getConfig()
    const name = cleanFolderName(req.body.name)
    const desc = String(req.body.desc || '').trim().slice(0, 600)
    if (!name || !desc) return back(res, '/einstellungen#ordner', { err: 'Name und Beschreibung angeben.' })
    if (cfg.categories.some(c => c.name.toLowerCase() === name.toLowerCase())) return back(res, '/einstellungen#ordner', { err: 'Diesen Ordner gibt es schon.' })
    if (cfg.categories.filter(c => c.custom).length >= 40) return back(res, '/einstellungen#ordner', { err: 'Höchstens 40 eigene Ordner.' })
    const id = 'c_' + crypto.randomBytes(5).toString('hex')
    saveConfig({ categories: [...cfg.categories.map(c => ({ id: c.id, name: c.name, desc: c.desc, off: c.off })), { id, name, desc, off: false }] })
    log('info', `Eigener Ordner „${name}“ angelegt`)
    back(res, '/einstellungen#ordner', { msg: `Ordner „${name}“ angelegt – er erscheint beim nächsten Durchlauf in den scharf geschalteten Postfächern.` })
  })
  app.post('/einstellungen/sicherheit', async (req, res) => {
    const b = req.body
    const lists = (v) => String(v || '').split(/\s+/).map(x => x.trim().toLowerCase()).filter(x => /^[a-z0-9.-]+\.[a-z]{2,}$/.test(x)).slice(0, 5).join('\n')
    saveConfig({ security: {
      phishThreshold: int(b.phishThreshold, 20, 300, 60),
      warnThreshold: int(b.warnThreshold, 5, 300, 30),
      blockDangerous: b.blockDangerous === '1',
      spamHeader: b.spamHeader === '1',
      dnsbl: b.dnsbl === '1',
      ipLists: lists(b.ipLists),
      domainLists: lists(b.domainLists),
      dnsServer: parseDnsServers(b.dnsServer).join(', '),
      brands: String(b.brands || '').slice(0, 2000)
    } })
    if (String(b.dnsServer || '').trim() && !parseDnsServers(b.dnsServer).length) return back(res, '/einstellungen#sicherheit', { err: 'DNS-Server ungültig – bitte eine IP-Adresse eintragen (z. B. 192.168.1.1).' })
    if (b.next !== 'test') return back(res, '/einstellungen#sicherheit', { msg: 'Gespeichert.' })
    const t = await testBlocklists(getConfig().security)
    const LBL = { ok: 'funktioniert', blocked: 'gesperrt (dieser DNS-Server wird vom Betreiber abgelehnt)', noanswer: 'keine Antwort', nohit: 'antwortet nicht richtig (Testeintrag fehlt)', unknown: 'erreichbar (kein Testeintrag bekannt)' }
    const lines = t.results.map(r => `${r.list}: ${LBL[r.state]}`).join(' · ')
    const bad = t.results.some(r => r.state === 'blocked' || r.state === 'noanswer' || r.state === 'nohit')
    if (!t.results.some(r => r.state === 'blocked')) setStatus({ dnsWarning: null })
    const via = `DNS ${t.auto ? 'automatisch ' : ''}${t.servers.join(', ')}`
    back(res, '/einstellungen#sicherheit', bad ? { err: `Gespeichert. Test über ${via} – ${lines}` } : { msg: `Gespeichert. Test über ${via} – ${lines}` })
  })

  app.post('/einstellungen/aufraeumen', (req, res) => {
    const b = req.body
    const cleanup = { spam: int(b.spam, 0, 3650, 0), verdacht: int(b.verdacht, 0, 3650, 0), mode: b.mode === 'delete' ? 'delete' : 'trash' }
    saveConfig({ cleanup })
    const cat = b.leeren === 'spam' || b.leeren === 'verdacht' ? b.leeren : null
    if (!cat) return back(res, '/einstellungen#aufraeumen', { msg: 'Gespeichert.' })
    const live = listAccounts().filter(a => a.enabled && a.mode === 'live')
    if (!live.length) return back(res, '/einstellungen#aufraeumen', { err: 'Kein Postfach ist scharf geschaltet – im Probelauf wird nichts gelöscht.' })
    for (const a of live) requestEmpty(a.id, cat)
    log('info', `„${targetLabel(cat, getConfig())}“ leeren angefordert (${cleanup.mode === 'delete' ? 'endgültig' : 'Papierkorb'})`)
    runOnce('Ordner leeren')
    back(res, '/einstellungen#aufraeumen', { msg: `Wird beim Durchlauf erledigt (gerade gestartet) – Ergebnis im Protokoll.` })
  })

  app.post('/einstellungen/passwort', async (req, res) => {
    const u = getUser(req.session.userId)
    if (!u || !(await verifyPassword(String(req.body.old || ''), u.hash))) return back(res, '/einstellungen#konto', { err: 'Aktuelles Passwort falsch.' })
    try { await changePassword(u.id, String(req.body.pw || ''), req.session.tokenHash) } catch (e) { return back(res, '/einstellungen#konto', { err: errText(e) }) }
    back(res, '/einstellungen#konto', { msg: 'Passwort geändert – andere Geräte sind abgemeldet.' })
  })
  app.post('/einstellungen/notfallcodes', (req, res) => {
    const r = checkSecondFactor(req.session, req.body.code, { stepup: true, ip: req.ip })
    if (r.error === 'locked') return mfaLocked(req, res, r.until)
    if (r.error === 'gone') return res.redirect(303, '/anmelden')
    if (r.error) return back(res, '/einstellungen#konto', { err: r.error })
    const codes = regenerateRecovery(req.session.userId)
    log('info', 'Neue Notfallcodes erzeugt')
    res.send(page({
      title: 'Notfallcodes', session: req.session, path: '/einstellungen',
      body: `<section class="card narrow"><h1>Neue Notfallcodes</h1><p>Die alten gelten nicht mehr. <b>Jetzt ausdrucken oder abschreiben</b> – sie werden nur dieses eine Mal angezeigt.</p>
      <ul class="codes">${codes.map(c => `<li class="mono">${esc(c)}</li>`).join('')}</ul>
      <div class="row wrap"><button class="btn" data-print>Drucken</button><a class="btn primary" href="/einstellungen#konto">Fertig</a></div></section>`
    }))
  })

  app.use((req, res) => res.status(404).send(page({ title: 'Nicht gefunden', body: '<h1>Nicht gefunden</h1><p><a href="/">Zur Startseite</a></p>', session: req.session })))
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    log('error', `Fehler bei ${req.method} ${req.path}: ${errText(err)}`)
    res.status(err.status === 413 ? 413 : 500).send(page({ title: 'Fehler', body: `<h1>Etwas ist schiefgegangen</h1><p>${esc(err.status === 413 ? 'Die Daten sind zu groß.' : 'Bitte noch einmal versuchen – Details im Protokoll.')}</p><p><a href="/">Zur Startseite</a></p>`, session: req.session }))
  })
  return app
}
