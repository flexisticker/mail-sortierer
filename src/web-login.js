// Anmeldung: Ersteinrichtung, Passwort, Zwei-Faktor (Pflicht), neues Passwort nach Zurücksetzen, Abmelden.
import { page, esc, csrf } from './html.js'
import { hasUsers, createUser, login, logout, setOwnPassword, enrollSecret, finishEnroll, checkSecondFactor, getUser, setMfaLockHook, mfaLockText, MFA_MAX } from './auth.js'
import { otpauthUri, qrSvg } from './totp.js'
import { sysLog } from './db.js'
import { shield, loginTrap, checkLoginForm } from './shield.js'
import { COOKIE, sessionCookie, clearCookie, cookie, back, flash } from './webutil.js'

const STAGE_PAGE = { pw: '/anmelden/passwort', enroll: '/anmelden/einrichten-2fa', mfa: '/anmelden/code', full: '/' }
const goStage = (res, stage) => res.redirect(303, STAGE_PAGE[stage] || '/')
const noticeBox = (s) => s && s.notice ? `<div class="alert info">${esc(s.notice)}</div>` : ''

// 10. falscher Zwei-Faktor-Code: IP sofort sperren (Heimnetz/Ausnahmen bleiben frei – dort greift die Kontosperre)
setMfaLockHook((ip, u) => shield.strike(ip, 'login', { where: 'app', path: '/anmelden/code', points: 10, detail: `${MFA_MAX} falsche Zwei-Faktor-Codes (${String(u.name).slice(0, 40)})` }))

/** Konto wegen falscher 2FA-Codes gesperrt: Cookie weg, zurück zur Anmeldung mit Hinweis */
export function mfaLocked (req, res, until) {
  res.set('Set-Cookie', clearCookie(req.secure))
  back(res, '/anmelden', { err: mfaLockText(until) })
}

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
      body: `<section class="card narrow wide-narrow enroll"><h1>Zwei-Faktor-Anmeldung einrichten</h1>${noticeBox(req.session)}
      <p>Damit niemand mit deinem Passwort allein an deine Mails kommt, brauchst du zusätzlich einen 6-stelligen Code aus einer <b>Authenticator-App</b> auf deinem Handy (z. B. <b>Authy</b>, Google Authenticator oder Microsoft Authenticator – alle kostenlos im Play Store bzw. App Store). Der Code ändert sich alle 30 Sekunden.</p>

      <details class="way" data-way="handy" open><summary><b>Ich richte am Handy ein</b> <span class="muted small">(diese Seite ist auf dem Handy offen)</span></summary>
        <p class="muted small">Den QR-Code kannst du nicht scannen, weil er auf demselben Bildschirm steht. Stattdessen kopierst du den Schlüssel in die App:</p>
        <ol class="steps-big">
          <li><b>Schlüssel kopieren:</b>
            <div class="copyrow"><input class="mono keybox" id="key2fa" value="${esc(sec)}" readonly aria-label="Schlüssel"><button type="button" class="btn primary" data-copy="key2fa">Kopieren</button></div>
            <span class="muted small">Klappt „Kopieren“ nicht: lange auf das Feld drücken → „Alles auswählen“ → „Kopieren“.</span></li>
          <li><b>Authenticator-App öffnen</b> (z. B. Authy) und einen <b>neuen Eintrag</b> anlegen – in Authy über das <b>+</b> bzw. „Konto hinzufügen“.</li>
          <li><b>„Schlüssel manuell eingeben“</b> wählen (in Authy „Enter key manually“ / „Code manuell eingeben“, nicht „QR-Code scannen“).</li>
          <li>Ins Feld für den Schlüssel <b>lange drücken → „Einfügen“</b>. Als Name z. B. <b>Postwart</b>, falls gefragt: <b>zeitbasiert, 6 Ziffern, 30 Sekunden</b> → speichern.</li>
          <li>Die App zeigt jetzt einen <b>6-stelligen Code</b>. In Authy: auf den Eintrag tippen, dann auf <b>„Kopieren“</b> bzw. auf den Code – in Google Authenticator: lange auf den Code drücken.</li>
          <li>Zurück in den Browser wechseln und den Code unten bei „Code aus der App“ <b>einfügen</b> (oder abtippen) → <b>Bestätigen</b>. Läuft der Code gerade ab, einfach den nächsten nehmen.</li>
        </ol>
        <p class="muted small">Google Authenticator, 2FAS u. a. können den Eintrag auch direkt übernehmen: <a class="btn sm" href="${esc(uri)}">In Authenticator-App öffnen</a> (öffnet sich nichts, den Weg oben nehmen).</p>
      </details>

      <details class="way" data-way="pc"><summary><b>Ich richte am PC ein</b> <span class="muted small">(Handy liegt daneben)</span></summary>
        <ol class="steps-big">
          <li>Authenticator-App auf dem Handy öffnen und einen <b>neuen Eintrag</b> anlegen (Authy: <b>+</b> → „QR-Code scannen“).</li>
          <li>Diesen QR-Code mit dem Handy <b>scannen</b>:</li>
        </ol>
        <div class="qrbox">${qrSvg(uri)}</div>
        <p class="muted small">Scannen geht nicht? Diesen Schlüssel in der App von Hand eingeben: <span class="mono">${esc(sec.replace(/(.{4})/g, '$1 ').trim())}</span> (zeitbasiert, 6 Ziffern, 30 Sekunden).</p>
        <ol class="steps-big" start="3"><li>Den 6-stelligen Code aus der App unten eingeben → <b>Bestätigen</b>.</li></ol>
      </details>

      <form method="post" action="/anmelden/einrichten-2fa" class="form enroll-code">${csrf(req.session)}
        <label><b>Code aus der App</b><input name="code" inputmode="numeric" pattern="[0-9 ]{6,7}" maxlength="7" required autocomplete="one-time-code" placeholder="123456"></label>
        <button class="btn primary">Bestätigen</button></form>
      <details class="way small"><summary>Hilfe: der Code wird nicht angenommen</summary>
        <ul class="muted small">
          <li>Die <b>Uhrzeit am Handy</b> muss stimmen: Einstellungen → Datum und Uhrzeit → „Automatisch“ einschalten.</li>
          <li>Immer den <b>aktuellen</b> Code nehmen – jeder gilt nur 30 Sekunden (kurz davor und danach wird er noch angenommen).</li>
          <li>Zeigt die App 7 oder 8 Ziffern, den Eintrag löschen und mit <b>6 Ziffern</b> neu anlegen.</li>
          <li>Authy fragt beim ersten Start nach Handynummer und E-Mail – das ist für Authy selbst, nicht für Postwart.</li>
          <li>Nach fünf falschen Codes musst du dich neu anmelden, nach zehn ist die Anmeldung 24 Stunden gesperrt. Der Schlüssel bleibt gleich, bis die Einrichtung geklappt hat.</li>
        </ul>
      </details>
      <form method="post" action="/abmelden">${csrf(req.session)}<button class="link">Abbrechen und abmelden</button></form></section>`
    }))
  })
  app.post('/anmelden/einrichten-2fa', inStage('enroll'), (req, res) => {
    const r = finishEnroll(req.session, req.body.code, { ip: req.ip })
    if (r.error === 'locked') return mfaLocked(req, res, r.until)
    if (r.error === 'gone') return lostSession(req, res)
    if (r.error) return back(res, '/anmelden/einrichten-2fa', { err: r.error })
    shield.trust(req.ip)
    sessionAfterFull(req, res)
    res.send(page({
      title: 'Notfallcodes',
      body: `<section class="card narrow"><h1>Fertig – bitte Notfallcodes aufbewahren</h1>
      <p>Falls das Handy verloren geht, kommst du mit einem dieser Codes herein (jeder Code gilt einmal). <b>Jetzt ausdrucken oder abschreiben</b> (oder ein Foto auf einem anderen Gerät) – sie werden nur dieses eine Mal angezeigt.</p><p class="muted small">Tipp Authy: In der App lässt sich eine verschlüsselte Sicherung einschalten – dann sind die Codes auch auf einem neuen Handy wieder da.</p>
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
    const r = checkSecondFactor(req.session, req.body.code, { ip: req.ip })
    if (r.error === 'locked') return mfaLocked(req, res, r.until)
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
