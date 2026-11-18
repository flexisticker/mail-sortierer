// Anmeldung: Ersteinrichtung, Passwort, Zwei-Faktor (Pflicht), neues Passwort nach Zurücksetzen, Abmelden.
import { page, esc, csrf } from './html.js'
import { hasUsers, createUser, login, logout, setOwnPassword, enrollSecret, finishEnroll, checkSecondFactor, getUser } from './auth.js'
import { otpauthUri, qrSvg } from './totp.js'
import { sysLog } from './db.js'
import { shield, loginTrap, checkLoginForm } from './shield.js'
import { COOKIE, sessionCookie, clearCookie, cookie, back, flash } from './webutil.js'

const STAGE_PAGE = { pw: '/anmelden/passwort', enroll: '/anmelden/einrichten-2fa', mfa: '/anmelden/code', full: '/' }
const goStage = (res, stage) => res.redirect(303, STAGE_PAGE[stage] || '/')
const noticeBox = (s) => s && s.notice ? `<div class="alert info">${esc(s.notice)}</div>` : ''

export function registerLogin (app) {
  // --- Ersteinrichtung (nur solange es noch kein Konto gibt) ---
  app.get('/einrichten', (req, res) => {
    if (hasUsers()) return res.redirect('/anmelden')
    res.send(page({
      title: 'Einrichten', ...flash(req),
      body: `<section class="card narrow"><h1>Willkommen</h1>
      <p>Lege das Verwalter-Konto an. Weitere Nutzer (z. B. Familie) legst du danach unter „Verwaltung“ an. Gleich nach dem Anlegen richtest du die Zwei-Faktor-Anmeldung mit einer Authenticator-App ein.</p>
      <form method="post" action="/einrichten" class="form">
        <label>Benutzername<input name="name" required maxlength="40" autocomplete="username"></label>
        <label>Passwort (mind. 10 Zeichen)<input name="pw" type="password" required minlength="10" autocomplete="new-password"></label>
        <label>Passwort wiederholen<input name="pw2" type="password" required minlength="10" autocomplete="new-password"></label>
        <button class="btn primary">Konto anlegen</button></form></section>`
    }))
  })
  app.post('/einrichten', async (req, res) => {
    if (hasUsers()) return res.redirect('/anmelden')
    const name = String(req.body.name || '').trim().slice(0, 40)
    if (String(req.body.pw || '').length < 10) return back(res, '/einrichten', { err: 'Passwort zu kurz (mind. 10 Zeichen).' })
    if (req.body.pw !== req.body.pw2) return back(res, '/einrichten', { err: 'Die Passwörter stimmen nicht überein.' })
    try { await createUser(name, req.body.pw, { role: 'admin' }) } catch (e) { return back(res, '/einrichten', { err: e.message }) }
    sysLog('info', `Verwalter-Konto „${name}“ angelegt`)
    back(res, '/anmelden', { msg: 'Konto angelegt – bitte anmelden.' })
  })

  // --- Anmelden ---
  app.get('/anmelden', (req, res) => {
    if (!hasUsers()) return res.redirect('/einrichten')
    if (req.session) return goStage(res, req.session.stage)
    res.send(page({
      title: 'Anmelden', ...flash(req),
      body: `<section class="card narrow"><h1>Anmelden</h1>
      <form method="post" action="/anmelden" class="form">${loginTrap()}
        <label>Benutzername<input name="name" required autocomplete="username" autofocus maxlength="40"></label>
        <label>Passwort<input name="pw" type="password" required autocomplete="current-password" maxlength="200"></label>
        <label class="check"><input type="checkbox" name="bleiben" value="1" checked> Angemeldet bleiben (30 Tage, nur auf eigenen Geräten)</label>
        <button class="btn primary">Weiter</button></form>
      <p class="muted small">Danach fragt Postwart den Code aus deiner Authenticator-App ab.</p>
      <a class="hpf" href="/intern/kontakt" tabindex="-1" aria-hidden="true">Kontakt</a></section>`
    }))
  })
  app.post('/anmelden', async (req, res) => {
    const bad = checkLoginForm(req)
    if (bad) return back(res, '/anmelden', { err: bad })
    const name = String(req.body.name || '').trim()
    const r = await login(name, String(req.body.pw || ''), req.ip, req.body.bleiben === '1')
    if (r.failed) shield.strike(req.ip, 'login', { where: 'app', path: '/anmelden', ua: req.get('user-agent') || '', detail: name.slice(0, 40) })
    if (r.error) return back(res, '/anmelden', { err: r.error })
    res.set('Set-Cookie', sessionCookie(r.token, r.remember, req.secure))
    goStage(res, r.stage)
  })

  // Hilfsfunktion: nur in der passenden Stufe
  const inStage = (stage) => (req, res, next) => {
    if (!req.session) return res.redirect('/anmelden')
    if (req.session.stage !== stage) return goStage(res, req.session.stage)
    next()
  }
  const lostSession = (req, res) => {
    res.set('Set-Cookie', clearCookie(req.secure))
    shield.strike(req.ip, 'login', { where: 'app', path: req.originalUrl, ua: req.get('user-agent') || '', detail: 'zu viele falsche Codes' })
    back(res, '/anmelden', { err: 'Zu viele falsche Codes – bitte neu anmelden.' })
  }

  // --- Neues Passwort (nach Zurücksetzen durch den Verwalter / Notfall-Zugang) ---
  app.get('/anmelden/passwort', inStage('pw'), (req, res) => {
    res.send(page({
      title: 'Neues Passwort', ...flash(req),
      body: `<section class="card narrow"><h1>Eigenes Passwort vergeben</h1>${noticeBox(req.session)}
      <form method="post" action="/anmelden/passwort" class="form">${csrf(req.session)}
        <input type="text" name="username" value="${esc(req.session.name)}" autocomplete="username" hidden>
        <label>Neues Passwort (mind. 10 Zeichen)<input name="pw" type="password" required minlength="10" maxlength="200" autocomplete="new-password" autofocus></label>
        <label>Wiederholen<input name="pw2" type="password" required minlength="10" maxlength="200" autocomplete="new-password"></label>
        <button class="btn primary">Speichern</button></form>
      <form method="post" action="/abmelden">${csrf(req.session)}<button class="link">Abbrechen und abmelden</button></form></section>`
    }))
  })
  app.post('/anmelden/passwort', inStage('pw'), async (req, res) => {
    if (req.body.pw !== req.body.pw2) return back(res, '/anmelden/passwort', { err: 'Die Passwörter stimmen nicht überein.' })
    try { goStage(res, await setOwnPassword(req.session, String(req.body.pw || ''))) } catch (e) { back(res, '/anmelden/passwort', { err: e.message }) }
  })

  // --- Zwei-Faktor einrichten (Pflicht) ---
  app.get('/anmelden/einrichten-2fa', inStage('enroll'), (req, res) => {
    const sec = enrollSecret(req.session.userId)
    const uri = otpauthUri(sec, req.session.name)
    res.send(page({
      title: 'Zwei-Faktor einrichten', ...flash(req),
      body: `<section class="card narrow"><h1>Zwei-Faktor-Anmeldung einrichten</h1>${noticeBox(req.session)}
      <p>Damit niemand mit deinem Passwort allein an deine Mails kommt, brauchst du zusätzlich einen Code vom Handy.</p>
      <ol class="steps-plain">
        <li>Authenticator-App öffnen (z. B. Google Authenticator, Microsoft Authenticator, am iPhone „Passwörter“ → Bestätigungscodes).</li>
        <li>Neuen Eintrag hinzufügen und diesen QR-Code scannen:</li>
      </ol>
      <div class="qrbox">${qrSvg(uri)}</div>
      <details><summary>QR-Code geht nicht? Schlüssel von Hand eingeben</summary><p class="mono big">${esc(sec.replace(/(.{4})/g, '$1 ').trim())}</p><p class="muted small">Art: zeitbasiert, 6 Ziffern, 30 Sekunden.</p></details>
      <form method="post" action="/anmelden/einrichten-2fa" class="form">${csrf(req.session)}
        <label>3. Den 6-stelligen Code aus der App eingeben<input name="code" inputmode="numeric" pattern="[0-9 ]{6,7}" maxlength="7" required autocomplete="one-time-code" autofocus></label>
        <button class="btn primary">Bestätigen</button></form>
      <form method="post" action="/abmelden">${csrf(req.session)}<button class="link">Abbrechen und abmelden</button></form></section>`
    }))
  })
  app.post('/anmelden/einrichten-2fa', inStage('enroll'), (req, res) => {
    const r = finishEnroll(req.session, req.body.code)
    if (r.error === 'gone') return lostSession(req, res)
    if (r.error) return back(res, '/anmelden/einrichten-2fa', { err: r.error })
    shield.trust(req.ip)
    sessionAfterFull(req, res)
    res.send(page({
      title: 'Notfallcodes',
      body: `<section class="card narrow"><h1>Fertig – bitte Notfallcodes aufbewahren</h1>
      <p>Falls das Handy verloren geht, kommst du mit einem dieser Codes herein (jeder Code gilt einmal). <b>Jetzt ausdrucken oder abschreiben</b> – sie werden nur dieses eine Mal angezeigt.</p>
      <ul class="codes">${r.codes.map(c => `<li class="mono">${esc(c)}</li>`).join('')}</ul>
      <div class="row wrap"><button class="btn" data-print>Drucken</button><a class="btn primary" href="/">Weiter zu Postwart</a></div></section>`
    }))
  })

  // --- Code bei der Anmeldung ---
  app.get('/anmelden/code', inStage('mfa'), (req, res) => {
    res.send(page({
      title: 'Code eingeben', ...flash(req),
      body: `<section class="card narrow"><h1>Code aus der App</h1>${noticeBox(req.session)}
      <form method="post" action="/anmelden/code" class="form">${csrf(req.session)}
        <label>6-stelliger Code<input name="code" inputmode="numeric" maxlength="20" required autocomplete="one-time-code" autofocus></label>
        <button class="btn primary">Anmelden</button></form>
      <p class="muted small">Handy nicht zur Hand? Einen deiner Notfallcodes (z. B. <code>abcd-efgh-jkmn</code>) ins selbe Feld eingeben. Alles verloren? Der Verwalter kann deinen Zugang zurücksetzen.</p>
      <form method="post" action="/abmelden">${csrf(req.session)}<button class="link">Abbrechen</button></form></section>`
    }))
  })
  app.post('/anmelden/code', inStage('mfa'), (req, res) => {
    const r = checkSecondFactor(req.session, req.body.code)
    if (r.error === 'gone') return lostSession(req, res)
    if (r.error) return back(res, '/anmelden/code', { err: r.error })
    shield.trust(req.ip)
    sessionAfterFull(req, res)
    if (r.how === 'notfallcode') return back(res, '/einstellungen#konto', { err: `Mit Notfallcode angemeldet – noch ${r.left} übrig. Bitte unter „Konto“ neue Notfallcodes erzeugen${r.left < 3 ? ' (es sind nur noch wenige)' : ''}.` })
    res.redirect(303, '/')
  })

  app.post('/abmelden', (req, res) => {
    logout(cookie(req, COOKIE))
    res.set('Set-Cookie', clearCookie(req.secure))
    res.redirect(303, '/anmelden')
  })
}

// Nach vollständiger Anmeldung das Cookie mit der richtigen Laufzeit neu setzen
function sessionAfterFull (req, res) {
  const tok = cookie(req, COOKIE)
  res.set('Set-Cookie', sessionCookie(tok, req.session.remember, req.secure))
  const u = getUser(req.session.userId)
  sysLog('info', `Anmeldung: ${u.name} von ${req.ip}`)
}
