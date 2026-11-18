// Verwaltung (nur Verwalter): Nutzer, Zugang wiederherstellen, gemeinsame KI, Angriffsschutz, Sicherheits-Check.
// Von außen nur nach erneuter Code-Eingabe (10 Minuten gültig); KI und Angriffsschutz nur aus dem Heimnetz änderbar.
import { page, esc, csrf, fmtDate, options } from './html.js'
import { sysdb, withUser } from './db.js'
import {
  listUsers, getUser, createUser, oneTimePassword, FEATURES, FULL_FEATURES, SIMPLE_FEATURES, featuresOf, validName,
  adminResetPassword, adminReset2fa, adminLogoutAll, adminSetDisabled, adminSetUser, adminDeleteUser, checkSecondFactor, stepupValid, isLockedName, unlockName
} from './auth.js'
import { shield, KINDS, saveShieldConfig, manualBan, selfCheck } from './shield.js'
import { checkUpdate } from './updates.js'
import { keySource, currentKeyBase64, KEY_ENV } from './secrets.js'
import { getConfig, saveConfig, targetLabel } from './config.js'
import { listModels, queueLength } from './ollama.js'
import { classify } from './classify.js'
import { listAccounts } from './accounts.js'
import { back, int, errText, flash } from './webutil.js'
import { PLATFORM } from './config.js'

const tabs = (active) => `<nav class="tabs">${[['/verwaltung', 'Nutzer'], ['/verwaltung/ki', 'Gemeinsame KI'], ['/verwaltung/schutz', 'Angriffsschutz'], ['/verwaltung/check', 'Sicherheits-Check']]
  .map(([h, l]) => `<a href="${h}"${h === active ? ' class="on"' : ''}>${l}</a>`).join('')}</nav>`

export function registerAdmin (app) {
  // Zugang zur Verwaltung: Verwalter; von außen nur mit frischer Code-Bestätigung
  app.use('/verwaltung', (req, res, next) => {
    const s = req.session
    if (!s.admin) return res.status(403).send(page({ title: 'Kein Zugriff', body: '<h1>Kein Zugriff</h1><p>Nur der Verwalter kann das öffnen.</p>', session: s }))
    if (req.path === '/bestaetigen') return next()
    if (!s.home && !stepupValid(s)) return req.method === 'GET' ? res.redirect(303, '/verwaltung/bestaetigen?weiter=' + encodeURIComponent(req.originalUrl)) : res.redirect(303, '/verwaltung/bestaetigen')
    next()
  })
  const homeOnly = (req, res, next) => {
    if (req.session.home) return next()
    if (req.method === 'GET') return next() // ansehen ja, ändern nein
    back(res, req.path, { err: 'Diese Einstellung lässt sich nur aus dem Heimnetz ändern.' })
  }

  app.get('/verwaltung/bestaetigen', (req, res) => {
    const weiter = /^\/verwaltung(\/|$|\?)/.test(String(req.query.weiter || '')) ? String(req.query.weiter) : '/verwaltung'
    res.send(page({
      title: 'Bestätigen', session: req.session, path: '/verwaltung', ...flash(req),
      body: `<section class="card narrow"><h1>System-Bereich bestätigen</h1>
      <p>Du bist nicht im Heimnetz. Zur Sicherheit bitte den aktuellen Code aus deiner Authenticator-App eingeben (gilt 10 Minuten).</p>
      <form method="post" action="/verwaltung/bestaetigen" class="form">${csrf(req.session)}<input type="hidden" name="weiter" value="${esc(weiter)}">
        <label>Code<input name="code" inputmode="numeric" maxlength="20" required autocomplete="one-time-code" autofocus></label>
        <button class="btn primary">Bestätigen</button></form></section>`
    }))
  })
  app.post('/verwaltung/bestaetigen', (req, res) => {
    const weiter = /^\/verwaltung(\/|$|\?)/.test(String(req.body.weiter || '')) ? String(req.body.weiter) : '/verwaltung'
    const r = checkSecondFactor(req.session, req.body.code, { stepup: true })
    if (r.error === 'gone') return res.redirect(303, '/anmelden')
    if (r.error) return back(res, '/verwaltung/bestaetigen?weiter=' + encodeURIComponent(weiter), { err: r.error })
    res.redirect(303, weiter)
  })

  // ---------------- Nutzer ----------------
  const featureBoxes = (f) => Object.entries(FEATURES).map(([k, label]) => `<label class="check"><input type="checkbox" name="f_${k}" value="1"${f[k] ? ' checked' : ''}> ${esc(label)}</label>`).join('')
  const readFeatures = (b) => Object.fromEntries(Object.keys(FEATURES).map(k => [k, b['f_' + k] === '1']))

  app.get('/verwaltung', (req, res) => {
    const s = req.session
    const users = listUsers()
    const sessions = Object.fromEntries(sysdb.prepare("SELECT user_id, COUNT(*) n FROM sessions WHERE expires_at > ? AND stage = 'full' GROUP BY user_id").all(Date.now()).map(r => [r.user_id, r.n]))
    const accCount = (u) => { try { return withUser(u, () => listAccounts().length) } catch { return 0 } }
    const body = `<h1>System</h1>${tabs('/verwaltung')}
    ${s.home ? '' : '<div class="alert info">Du bist von außen angemeldet. Nutzer verwalten geht (bestätigt), gemeinsame KI und Angriffsschutz lassen sich nur aus dem Heimnetz ändern.</div>'}
    <section class="card"><h2>Nutzer</h2>
      <p class="muted">Jeder Nutzer hat eine eigene Oberfläche mit eigenen Postfächern, Regeln und Gelerntem. Du siehst hier keine Mails und keine Postfach-Passwörter der anderen – du verwaltest nur die Zugänge. Die KI (Ollama) teilen sich alle.</p>
      ${users.map(u => { const f = featuresOf(u); return `<details class="acc"${String(req.query.offen) === String(u.id) ? ' open' : ''}><summary><b>${esc(u.display || u.name)}</b> <span class="muted small">${esc(u.name)}</span>
        ${u.role === 'admin' ? '<span class="pill info">Verwalter</span>' : ''}
        ${u.totp_on ? '<span class="pill good">2FA</span>' : '<span class="pill warn">2FA fehlt</span>'}
        ${u.must_change ? '<span class="pill warn">Einmal-Passwort</span>' : ''}${u.disabled ? '<span class="pill bad">gesperrt</span>' : ''}${isLockedName(u.name) ? '<span class="pill bad">Fehlversuche</span>' : ''}</summary>
        <dl class="facts"><dt>Zuletzt angemeldet</dt><dd>${u.last_login ? fmtDate(u.last_login) : 'noch nie'}</dd><dt>Angemeldete Geräte</dt><dd>${sessions[u.id] || 0}</dd>
          <dt>Postfächer</dt><dd>${accCount(u)}</dd><dt>Notfallcodes übrig</dt><dd>${(() => { try { return JSON.parse(u.recovery || '[]').length } catch { return 0 } })()}</dd>
          <dt>Bereiche</dt><dd>${Object.keys(FEATURES).filter(k => f[k]).map(k => esc(FEATURES[k].split(' (')[0])).join(', ') || 'nur Sortieren'}</dd></dl>
        <h3>Zugang wiederherstellen</h3>
        <form method="post" action="/verwaltung/nutzer/${u.id}" class="row wrap">${csrf(s)}
          <button class="btn" name="aktion" value="passwort" data-confirm="Neues Einmal-Passwort für ${esc(u.name)} erzeugen? Das alte Passwort gilt dann nicht mehr, alle Geräte werden abgemeldet.">Passwort zurücksetzen</button>
          <button class="btn" name="aktion" value="2fa" data-confirm="Zwei-Faktor von ${esc(u.name)} zurücksetzen (z. B. Handy verloren)? Bei der nächsten Anmeldung richtet ${esc(u.name)} die App neu ein.">2FA zurücksetzen</button>
          <button class="btn" name="aktion" value="abmelden" data-confirm="${esc(u.name)} auf allen Geräten abmelden?">Auf allen Geräten abmelden</button>
          ${isLockedName(u.name) ? '<button class="btn" name="aktion" value="entsperren-login">Fehlversuche zurücksetzen</button>' : ''}
          ${u.disabled ? '<button class="btn" name="aktion" value="entsperren">Entsperren</button>' : `<button class="btn ghost" name="aktion" value="sperren" data-confirm="${esc(u.name)} sperren? Anmelden geht dann nicht mehr, Sortieren läuft nicht mehr.">Sperren</button>`}
        </form>
        <h3>Einstellungen</h3>
        <form method="post" action="/verwaltung/nutzer/${u.id}" class="form two">${csrf(s)}<input type="hidden" name="aktion" value="speichern">
          <label>Anzeigename<input name="display" value="${esc(u.display || '')}" maxlength="60"></label>
          <label>Rolle<select name="role">${options([['user', 'Nutzer'], ['admin', 'Verwalter']], u.role)}</select></label>
          <fieldset class="span"><legend>Freigegebene Bereiche</legend>${featureBoxes(f)}</fieldset>
          <div class="row span"><button class="btn primary">Speichern</button></div></form>
        ${u.data ? `<form method="post" action="/verwaltung/nutzer/${u.id}" class="row">${csrf(s)}<input type="hidden" name="aktion" value="loeschen">
          <label class="check"><input type="checkbox" name="sicher" value="1" required> Alle Daten von ${esc(u.name)} in Postwart löschen (Postfächer, Gelerntes, Rechnungen) – die Mails im Postfach selbst bleiben</label>
          <button class="btn ghost" data-confirm="${esc(u.name)} endgültig löschen?">Nutzer löschen</button></form>` : '<p class="muted small">Dieses Konto nutzt die Haupt-Datenbank (erstes Konto) und lässt sich nicht löschen.</p>'}
      </details>` }).join('')}
    </section>
    <section class="card" id="neu"><h2>Nutzer anlegen</h2>
      <p class="muted">Du bekommst ein Einmal-Passwort angezeigt. Damit meldet sich der neue Nutzer an, vergibt ein eigenes Passwort und richtet seine Authenticator-App ein.</p>
      <form method="post" action="/verwaltung/nutzer" class="form two">${csrf(s)}
        <label>Benutzername (zum Anmelden)<input name="name" required maxlength="40" pattern="[A-Za-z0-9ÄÖÜäöüß._@-]{2,40}" placeholder="z. B. anna"></label>
        <label>Anzeigename<input name="display" maxlength="60" placeholder="z. B. Anna"></label>
        <label>Rolle<select name="role">${options([['user', 'Nutzer'], ['admin', 'Verwalter']], 'user')}</select></label>
        <fieldset class="span"><legend>Freigegebene Bereiche (Vorschlag für Familie: Mail-Programm, Aufräumen, Ordner – Sortierung läuft im Hintergrund)</legend>${featureBoxes(SIMPLE_FEATURES)}</fieldset>
        <div class="row span"><button class="btn primary">Anlegen</button></div></form></section>`
    res.send(page({ title: 'System', body, session: s, path: '/verwaltung', ...flash(req) }))
  })

  const showPassword = (req, res, u, pw, text) => res.send(page({
    title: 'Einmal-Passwort', session: req.session, path: '/verwaltung',
    body: `<section class="card narrow"><h1>Einmal-Passwort für ${esc(u.display || u.name)}</h1>
    <p>${esc(text)}</p><p class="mono big">${esc(pw)}</p>
    <p class="muted">Benutzername: <b>${esc(u.name)}</b>. Gib das Passwort persönlich oder per Telefon weiter (nicht per Mail). Bei der Anmeldung wird ein eigenes Passwort vergeben${u.totp_on ? '' : ' und die Authenticator-App eingerichtet'}. Es wird nur jetzt angezeigt.</p>
    <a class="btn primary" href="/verwaltung?offen=${u.id}">Fertig</a></section>`
  }))

  app.post('/verwaltung/nutzer', async (req, res) => {
    const b = req.body
    const name = String(b.name || '').trim()
    if (!validName(name)) return back(res, '/verwaltung#neu', { err: 'Benutzername: 2–40 Zeichen, nur Buchstaben, Ziffern und . _ - @' })
    try {
      const pw = oneTimePassword()
      const u = await createUser(name, pw, { role: b.role === 'admin' ? 'admin' : 'user', display: b.display, features: readFeatures(b), mustChange: true })
      sysdb.prepare('UPDATE users SET notice = ? WHERE id = ?').run('Willkommen! Bitte vergib ein eigenes Passwort und richte danach die Authenticator-App ein.', u.id)
      showPassword(req, res, u, pw, 'Der Nutzer ist angelegt.')
    } catch (e) { back(res, '/verwaltung#neu', { err: errText(e) }) }
  })

  app.post('/verwaltung/nutzer/:id', async (req, res) => {
    const s = req.session
    const u = getUser(int(req.params.id, 1, 1e9, 0))
    if (!u) return back(res, '/verwaltung', { err: 'Nutzer nicht gefunden.' })
    const to = `/verwaltung?offen=${u.id}`
    const own = u.id === s.userId
    try {
      switch (req.body.aktion) {
        case 'passwort': {
          if (own) return back(res, to, { err: 'Dein eigenes Passwort änderst du unter Einstellungen → Konto.' })
          return showPassword(req, res, getUser(u.id), await adminResetPassword(u.id, s.name), 'Das Passwort ist zurückgesetzt, alle Geräte sind abgemeldet.')
        }
        case '2fa':
          if (own) return back(res, to, { err: 'Deine eigene Zwei-Faktor-Anmeldung kannst du nicht hier zurücksetzen (Notfallcode oder Notfall-Zugang über die Konsole).' })
          adminReset2fa(u.id, s.name); return back(res, to, { msg: `Zwei-Faktor von ${u.name} zurückgesetzt – bei der nächsten Anmeldung wird die App neu eingerichtet.` })
        case 'abmelden': return back(res, to, { msg: `${adminLogoutAll(u.id, s.name, own ? s.tokenHash : null)} Gerät(e) abgemeldet.` })
        case 'entsperren-login': unlockName(u.name); return back(res, to, { msg: 'Fehlversuche zurückgesetzt.' })
        case 'sperren': if (own) return back(res, to, { err: 'Du kannst dich nicht selbst sperren.' }); adminSetDisabled(u.id, true, s.name); return back(res, to, { msg: `${u.name} gesperrt.` })
        case 'entsperren': adminSetDisabled(u.id, false, s.name); return back(res, to, { msg: `${u.name} entsperrt.` })
        case 'speichern':
          adminSetUser(u.id, { display: req.body.display, role: req.body.role, features: readFeatures(req.body) }, s.name)
          return back(res, to, { msg: 'Gespeichert.' })
        case 'loeschen':
          if (own) return back(res, to, { err: 'Du kannst dich nicht selbst löschen.' })
          if (req.body.sicher !== '1') return back(res, to, { err: 'Bitte das Häkchen setzen.' })
          adminDeleteUser(u.id, s.name); return back(res, '/verwaltung', { msg: `${u.name} gelöscht.` })
      }
      back(res, to, { err: 'Unbekannte Aktion.' })
    } catch (e) { back(res, to, { err: errText(e) }) }
  })

  // ---------------- Gemeinsame KI ----------------
  app.get('/verwaltung/ki', (req, res) => {
    const cfg = getConfig()
    const s = req.session
    const models = String(req.query.modelle || '').split(',').filter(Boolean)
    const body = `<h1>System</h1>${tabs('/verwaltung/ki')}
    <section class="card" id="ki"><h2>Gemeinsame KI (Ollama)</h2>
      <p class="muted">Die KI läuft bei dir – nichts geht ins Internet. Alle Nutzer teilen sich diese eine KI; die Anfragen laufen nacheinander (gerade in der Warteschlange: ${queueLength()}). ${PLATFORM === 'windows' ? 'Dafür „Ollama für Windows“ von ollama.com installieren (läuft dann unter <code>http://localhost:11434</code>) oder die Adresse eines Ollama-Servers im Netzwerk eintragen.' : 'Ollama-Adresse z. B. <code>http://&lt;Server-IP&gt;:11434</code>.'} Empfohlen mit Grafikkarte ab 6 GB: <code>qwen2.5:7b</code>; kleinere Karte: <code>qwen2.5:3b</code>.</p>
      ${s.home ? '' : '<div class="alert info">Nur aus dem Heimnetz änderbar.</div>'}
      <form method="post" action="/verwaltung/ki" class="form two">${csrf(s)}
        <label>Ollama-Adresse<input name="url" value="${esc(cfg.ollama.url)}" maxlength="200"></label>
        <label>Modell<input name="model" value="${esc(cfg.ollama.model)}" list="modelle" maxlength="100"><datalist id="modelle">${models.map(m => `<option value="${esc(m)}">`).join('')}</datalist></label>
        <label>Wartezeit je Mail (Sekunden)<input name="timeoutSec" type="number" value="${esc(cfg.ollama.timeoutSec)}" min="10" max="900"></label>
        <label>Kontextgröße (Tokens)<input name="numCtx" type="number" value="${esc(cfg.ollama.numCtx)}" min="1024" max="32768" step="512"></label>
        <div class="row span"><button class="btn primary" name="next" value="save"${s.home ? '' : ' disabled'}>Speichern</button><button class="btn" name="next" value="test"${s.home ? '' : ' disabled'}>Speichern &amp; testen</button></div>
      </form>
      ${models.length ? `<p class="small">Gefundene Modelle: ${models.map(esc).join(', ')}</p>` : ''}</section>`
    res.send(page({ title: 'Gemeinsame KI', body, session: s, path: '/verwaltung', ...flash(req) }))
  })
  app.post('/verwaltung/ki', homeOnly, async (req, res) => {
    const b = req.body
    const cfg = saveConfig({ ollama: { url: String(b.url || '').trim().slice(0, 200), model: String(b.model || '').trim().slice(0, 100), timeoutSec: int(b.timeoutSec, 10, 900, 120), numCtx: int(b.numCtx, 1024, 32768, 4096) } })
    if (b.next !== 'test') return back(res, '/verwaltung/ki', { msg: 'Gespeichert – gilt für alle Nutzer.' })
    let models = []
    try {
      models = await listModels(cfg)
      const names = models.map(m => m.name)
      if (!names.some(n => n === cfg.ollama.model || n === cfg.ollama.model + ':latest')) return back(res, `/verwaltung/ki?modelle=${encodeURIComponent(names.join(','))}`, { err: `Ollama erreichbar, aber Modell „${cfg.ollama.model}“ ist nicht geladen. Auf dem Server: ollama pull ${cfg.ollama.model}` })
      const t0 = Date.now()
      const d = await classify({ msgid: 'test', from_addr: 'versand@paketdienst.example', from_name: 'Paketdienst', domain: 'paketdienst.example', subject: 'Ihre Sendung 00340434161094042557 ist unterwegs', hints: 'Absender ist eine automatische Adresse', snippet: 'Guten Tag, Ihre Sendung wurde heute an uns übergeben und wird voraussichtlich morgen zugestellt.' }, { ...cfg, maxExamples: 0 })
      back(res, `/verwaltung/ki?modelle=${encodeURIComponent(names.join(','))}`, { msg: `KI antwortet in ${((Date.now() - t0) / 1000).toFixed(1)} s. Testmail (Paket) → „${targetLabel(d.decision, cfg)}“ (${d.confidence} %): ${d.reason}` })
    } catch (e) { back(res, `/verwaltung/ki?modelle=${encodeURIComponent(models.map(m => m.name).join(','))}`, { err: 'KI-Test fehlgeschlagen: ' + errText(e) }) }
  })

  // ---------------- Angriffsschutz ----------------
  app.get('/verwaltung/schutz', (req, res) => {
    const s = req.session
    const c = shield.config()
    const o = shield.overview({ events: 150 })
    const chk = (v) => v ? ' checked' : ''
    const de = (v) => new Date(v).toLocaleString('de-DE', { timeZone: 'Europe/Berlin', dateStyle: 'short', timeStyle: 'short' })
    const body = `<h1>System</h1>${tabs('/verwaltung/schutz')}
    <section class="card"><h2>Angriffsschutz</h2>
      <p class="muted">Ist Postwart von außen erreichbar, klopfen ständig Bots an. Wer in eine Falle tappt (z. B. <code>/wp-login.php</code>, <code>/.env</code>), Angriffsmuster schickt oder zu oft falsch anmeldet, sammelt Strafpunkte und wird gesperrt: 1 Stunde → 1 Tag → 7 Tage → 30 Tage. Heimnetz und erfolgreich angemeldete Geräte werden nie gesperrt.</p>
      <div class="kpis"><div><b>${o.stats.today}</b><span>heute</span></div><div><b>${o.stats.week}</b><span>7 Tage</span></div><div><b>${o.stats.month}</b><span>30 Tage</span></div><div><b>${o.bans.length}</b><span>gesperrt</span></div></div>
      ${s.home ? '' : '<div class="alert info">Einstellungen nur aus dem Heimnetz änderbar. Entsperren geht auch von außen.</div>'}
      <form method="post" action="/verwaltung/schutz" class="form two">${csrf(s)}
        <label class="check"><input type="checkbox" name="enabled" value="1"${chk(c.enabled !== false)}> Angriffsschutz an</label>
        <label class="check"><input type="checkbox" name="ban" value="1"${chk(c.ban !== false)}> Angreifer sperren (aus = nur protokollieren)</label>
        <label class="check"><input type="checkbox" name="allowLan" value="1"${chk(c.allowLan !== false)}> Heimnetz nie sperren (empfohlen)</label>
        <label class="check"><input type="checkbox" name="tarpit" value="1"${chk(c.tarpit !== false)}> Fallen antworten absichtlich langsam</label>
        <label class="span">Ausnahmen (IP oder Netz, je Zeile)<textarea name="allow" rows="2" maxlength="3000" placeholder="z. B. 203.0.113.7 oder 198.51.100.0/24">${esc((c.allow || []).join('\n'))}</textarea></label>
        <div class="row span"><button class="btn primary"${s.home ? '' : ' disabled'}>Speichern</button></div></form></section>
    <section class="card"><h2>Gesperrt (${o.bans.length})</h2>
      <div class="table-wrap"><table class="tbl"><thead><tr><th>Adresse</th><th>Grund</th><th>bis</th><th></th></tr></thead><tbody>
      ${o.bans.map(b => `<tr><td class="mono">${esc(b.ip)}${b.n > 1 ? ` <span class="pill warn">${b.n}. Sperre</span>` : ''}</td><td>${esc((KINDS[b.reason] || {}).label || b.reason)}${b.detail ? `<div class="muted small">${esc(b.detail)}</div>` : ''}</td><td class="nowrap">${de(b.until)}</td>
        <td><form method="post" action="/verwaltung/schutz/entsperren" class="inline">${csrf(s)}<input type="hidden" name="key" value="${esc(b.key)}"><button class="btn sm">Entsperren</button></form></td></tr>`).join('') || '<tr><td colspan="4" class="muted">Niemand gesperrt.</td></tr>'}
      </tbody></table></div>
      <form method="post" action="/verwaltung/schutz/sperren" class="row wrap">${csrf(s)}<input name="ip" placeholder="IP-Adresse" maxlength="60" required><input name="hours" type="number" min="1" max="8760" value="24"><button class="btn">Von Hand sperren (Stunden)</button></form></section>
    <section class="card"><h2>Letzte Ereignisse</h2>
      <div class="table-wrap"><table class="tbl"><tbody>
      ${o.events.map(e => `<tr><td class="nowrap">${de(e.at)}</td><td class="mono">${esc(e.ip)}</td><td>${esc((KINDS[e.kind] || {}).label || e.kind)}${e.allowed ? ` <span class="pill">${esc(e.allowed)} – nicht gezählt</span>` : ''}${e.banned ? ' <span class="pill bad">gesperrt</span>' : ''}<div class="muted small">${esc(e.path || e.detail || '')}</div></td></tr>`).join('') || '<tr><td class="muted">Noch nichts.</td></tr>'}
      </tbody></table></div>
      <form method="post" action="/verwaltung/schutz/leeren">${csrf(s)}<button class="btn ghost" data-confirm="Ereignisliste leeren? Sperren bleiben bestehen.">Liste leeren</button></form></section>`
    res.send(page({ title: 'Angriffsschutz', body, session: s, path: '/verwaltung', wide: true, ...flash(req) }))
  })
  app.post('/verwaltung/schutz', homeOnly, (req, res) => {
    try { saveShieldConfig(req.body); back(res, '/verwaltung/schutz', { msg: 'Gespeichert.' }) } catch (e) { back(res, '/verwaltung/schutz', { err: errText(e) }) }
  })
  app.post('/verwaltung/schutz/entsperren', (req, res) => {
    back(res, '/verwaltung/schutz', shield.unban(req.body.key) ? { msg: 'Entsperrt.' } : { err: 'Nicht gefunden.' })
  })
  app.post('/verwaltung/schutz/sperren', homeOnly, (req, res) => {
    try { const b = manualBan(req.body.ip, req.session.name, req.body.hours); back(res, '/verwaltung/schutz', { msg: `${b.ip} gesperrt.` }) } catch (e) { back(res, '/verwaltung/schutz', { err: errText(e) }) }
  })
  app.post('/verwaltung/schutz/leeren', homeOnly, (req, res) => { shield.clearEvents(); back(res, '/verwaltung/schutz', { msg: 'Geleert.' }) })

  // ---------------- Sicherheits-Check ----------------
  app.get('/verwaltung/check', (req, res) => {
    const s = req.session
    const list = selfCheck()
    const ICON = { ok: '✓', warn: '!', bad: '✕', info: 'i' }
    const body = `<h1>System</h1>${tabs('/verwaltung/check')}
    <section class="card"><h2>Sicherheits-Check</h2>
      <ul class="checks">${list.map(c => `<li class="ck-${c.state}"><span class="ck-ic">${ICON[c.state]}</span><div><b>${esc(c.title)}</b><div class="muted small">${esc(c.text)}</div></div></li>`).join('')}</ul>
      <div class="row wrap"><form method="post" action="/verwaltung/check/update">${csrf(s)}<button class="btn">Jetzt nach Updates suchen</button></form>
      ${keySource() === 'file' ? `<form method="post" action="/verwaltung/check/schluessel">${csrf(s)}<button class="btn"${s.home ? '' : ' disabled title="nur im Heimnetz"'} data-confirm="Den Schlüssel für die gespeicherten Passwörter anzeigen? Niemandem zeigen und nicht per Mail verschicken.">Schlüssel anzeigen (für die Variable)</button></form>` : ''}</div>
      <p class="muted small">Zusätzlich prüft GitHub jede Woche die Programm-Pakete und das Basis-Image mit den neuesten Lücken-Datenbanken; bei einem ernsten Fund kommt eine Mail und neue Versionen werden erst nach der Korrektur gebaut.</p></section>`
    res.send(page({ title: 'Sicherheits-Check', body, session: s, path: '/verwaltung', ...flash(req) }))
  })
  app.post('/verwaltung/check/schluessel', homeOnly, (req, res) => {
    if (keySource() !== 'file') return back(res, '/verwaltung/check', { err: 'Der Schlüssel liegt schon nicht mehr im Datenordner.' })
    res.set('Cache-Control', 'no-store')
    res.send(page({
      title: 'Schlüssel', session: req.session, path: '/verwaltung',
      body: `<section class="card narrow wide-narrow"><h1>Schlüssel für die gespeicherten Passwörter</h1>
      <p class="mono big">${esc(currentKeyBase64())}</p>
      <ol class="steps-plain">
        <li>Unraid → Docker → Postwart → <b>Edit</b> → unten „Add another Path, Port, Variable …“ → <b>Variable</b>.</li>
        <li>Name: <code>Schlüssel</code>, Key: <code>${KEY_ENV}</code>, Value: der Schlüssel oben (genau so, 44 Zeichen). <b>Apply</b>.</li>
        <li>Beim Neustart übernimmt Postwart die Variable und löscht die Schlüsseldatei aus dem Datenordner. Im Sicherheits-Check steht dann „getrennt abgelegt“.</li>
      </ol>
      <p class="muted small">Den Schlüssel zusätzlich offline aufbewahren (z. B. ausgedruckt beim Notfallblatt): ohne ihn sind die Postfach-Passwörter nach einer Wiederherstellung neu einzugeben. Die Variable später nicht ändern oder löschen – dann startet Postwart nicht, damit nichts verloren geht.</p>
      <a class="btn primary" href="/verwaltung/check">Fertig</a></section>`
    }))
  })
  app.post('/verwaltung/check/update', async (req, res) => {
    try { const r = await checkUpdate(); back(res, '/verwaltung/check', { msg: r.update ? `Update verfügbar: ${r.latest}` : `Aktuell (neueste Version ${r.latest || '?'}).` }) } catch (e) { back(res, '/verwaltung/check', { err: 'Update-Prüfung fehlgeschlagen: ' + errText(e) }) }
  })
}

export { FULL_FEATURES }
