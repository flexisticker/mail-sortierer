// Mails schreiben: Neu, Antworten, Allen antworten, Weiterleiten, Entwürfe; Signaturen verwalten.
import crypto from 'node:crypto'
import busboy from 'busboy'
import { page, esc, csrf, options } from './html.js'
import { listAccounts, getAccount, accountLabel, smtpOf, setDefaultSignatures } from './accounts.js'
import { readMessage, attachmentsOf, cleanMailHtml, textToHtml, listFolders } from './webmail.js'
import { parseRecipients, sendMessage, saveDraft, MAX_TOTAL, listSignatures, getSignature, saveSignature, deleteSignature } from './compose.js'
import { back, int, errText, flash } from './webutil.js'

// Seiten mit Editor dürfen Formatierungen (style-Attribute) anzeigen – Skripte bleiben verboten
const EDITOR_CSP = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; form-action 'self'; frame-ancestors 'self'; base-uri 'none'; object-src 'none'"
const q = (o) => new URLSearchParams(Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined && v !== '' && v !== null))).toString()
const fmtAddr = (list) => (list || []).map(x => x.name ? `${x.name} <${x.address}>` : x.address).join(', ')
const vals = (h) => (h && h.value) || []
const fmtLong = (d) => d ? new Date(d).toLocaleString('de-DE', { timeZone: 'Europe/Berlin', dateStyle: 'medium', timeStyle: 'short' }) : ''
const prefix = (p, s) => new RegExp(`^(${p}|re|aw|wg|fw|fwd):`, 'i').test(String(s || '').trim()) ? String(s || '').trim() : `${p}: ${String(s || '').trim()}`

function toolbar () {
  return `<div class="ed-tools" role="toolbar" aria-label="Formatierung">
    <button type="button" class="tb" data-cmd="bold" title="Fett (Strg+B)"><b>F</b></button>
    <button type="button" class="tb" data-cmd="italic" title="Kursiv (Strg+I)"><i>K</i></button>
    <button type="button" class="tb" data-cmd="underline" title="Unterstrichen (Strg+U)"><u>U</u></button>
    <button type="button" class="tb" data-cmd="strikeThrough" title="Durchgestrichen"><s>S</s></button>
    <select class="tb" data-cmd="fontSize" title="Schriftgröße"><option value="">Größe</option><option value="2">Klein</option><option value="3">Normal</option><option value="5">Groß</option><option value="6">Sehr groß</option></select>
    <select class="tb" data-cmd="formatBlock" title="Absatz"><option value="">Absatz</option><option value="p">Text</option><option value="h2">Überschrift</option><option value="h3">Zwischenüberschrift</option><option value="blockquote">Zitat</option></select>
    <label class="tb color" title="Textfarbe">A<input type="color" data-cmd="foreColor" value="#c0262d"></label>
    <button type="button" class="tb" data-cmd="insertUnorderedList" title="Aufzählung">• Liste</button>
    <button type="button" class="tb" data-cmd="insertOrderedList" title="Nummerierung">1. Liste</button>
    <button type="button" class="tb" data-cmd="justifyLeft" title="Linksbündig">⇤</button>
    <button type="button" class="tb" data-cmd="justifyCenter" title="Mittig">↔</button>
    <button type="button" class="tb" data-cmd="justifyRight" title="Rechtsbündig">⇥</button>
    <button type="button" class="tb" data-cmd="createLink" title="Link (Strg+K)">Link</button>
    <button type="button" class="tb" data-cmd="unlink" title="Link entfernen">Link weg</button>
    <button type="button" class="tb" data-image title="Bild einfügen (auch Strg+V oder hineinziehen)">Bild</button><input type="file" accept="image/png,image/jpeg,image/gif,image/webp" data-image-input hidden multiple>
    <button type="button" class="tb" data-cmd="removeFormat" title="Formatierung entfernen">⌫ Format</button>
    <button type="button" class="tb" data-cmd="undo" title="Rückgängig (Strg+Z)">↶</button>
    <button type="button" class="tb" data-cmd="redo" title="Wiederholen (Strg+Y)">↷</button>
  </div>`
}

export function registerCompose (app) {
  // ---------- Schreiben ----------
  async function prefill (req, acc, art, folder, uid) {
    const v = { to: '', cc: '', bcc: '', subject: '', html: '', inReplyTo: '', references: '', origAtts: [], refFolder: '', refUid: '', draftFolder: '', draftUid: '' }
    if (!uid) return v
    const known = (await listFolders(acc)).some(f => f.path === folder)
    if (!known) throw new Error('Ordner nicht gefunden.')
    const msg = await readMessage(acc, folder, uid, { markSeen: false })
    if (!msg) throw new Error('Die Mail gibt es nicht mehr.')
    const p = msg.parsed
    const own = new Set(listAccounts().map(a => String(a.user).toLowerCase()))
    const atts = attachmentsOf(p)
    const body = p.html ? cleanMailHtml(p.html, atts).html : textToHtml(p.text)
    const from = vals(p.from)[0] || { name: '', address: '' }
    v.refFolder = folder; v.refUid = uid
    if (art === 'entwurf') {
      v.to = fmtAddr(vals(p.to)); v.cc = fmtAddr(vals(p.cc)); v.bcc = fmtAddr(vals(p.bcc)); v.subject = p.subject || ''
      v.html = body; v.draftFolder = folder; v.draftUid = uid; v.inReplyTo = p.inReplyTo || ''; v.references = [].concat(p.references || []).join(' ')
      v.origAtts = atts.filter(a => !(a.related && a.cid) && !a.danger)
      v.keepSig = true
      return v
    }
    if (art === 'weiter') {
      v.subject = prefix('WG', p.subject)
      v.origAtts = atts.filter(a => !(a.related && a.cid) && !a.danger)
      v.quote = `<div data-zitat="1"><br><div>-------- Weitergeleitete Nachricht --------<br>Von: ${esc(from.name ? `${from.name} <${from.address}>` : from.address)}<br>Datum: ${esc(fmtLong(p.date))}<br>An: ${esc(fmtAddr(vals(p.to)))}<br>Betreff: ${esc(p.subject || '')}</div><br>${body}</div>`
      return v
    }
    const replyTo = vals(p.replyTo).length ? vals(p.replyTo) : vals(p.from)
    v.to = fmtAddr(replyTo)
    if (art === 'alle') {
      const seen = new Set(replyTo.map(x => x.address.toLowerCase()))
      v.cc = fmtAddr([...vals(p.to), ...vals(p.cc)].filter(x => x.address && !own.has(x.address.toLowerCase()) && !seen.has(x.address.toLowerCase()) && seen.add(x.address.toLowerCase())))
    }
    v.subject = prefix('AW', p.subject)
    v.inReplyTo = p.messageId || ''
    v.references = [...[].concat(p.references || []), p.messageId].filter(Boolean).slice(-20).join(' ')
    v.quote = `<div data-zitat="1"><br><div>Am ${esc(fmtLong(p.date))} schrieb ${esc(from.name || from.address)}:</div><blockquote style="margin: 0 0 0 8px; border-left: 2px solid #ccc; padding-left: 8px">${body}</blockquote></div>`
    return v
  }

  function renderCompose (req, res, acc, art, v, err) {
    const s = req.session
    const accs = listAccounts()
    const sigs = listSignatures()
    const sigId = v.signatur !== undefined ? Number(v.signatur) : (art === 'neu' ? acc.sig_new : acc.sig_reply) || 0
    const sig = sigId ? getSignature(sigId) : null
    const html = v.html || `<p><br></p>${!v.keepSig && sig ? `<div data-signatur="1"><br>-- <br>${sig.html}</div>` : ''}${v.quote || ''}`
    const smtp = smtpOf(acc)
    res.set('Content-Security-Policy', EDITOR_CSP)
    res.send(page({
      title: 'Neue Mail', session: s, path: '/post', wide: true, err,
      body: `<h1>${art === 'antwort' || art === 'alle' ? 'Antworten' : art === 'weiter' ? 'Weiterleiten' : art === 'entwurf' ? 'Entwurf bearbeiten' : 'Neue Mail'}</h1>
      ${!smtp.host || !smtp.pass ? `<div class="alert warn">Für dieses Postfach ist noch kein Postausgang eingerichtet. <a href="/einstellungen?offen=${acc.id}#postfaecher">Jetzt einrichten</a></div>` : ''}
      <form method="post" action="/post/senden" enctype="multipart/form-data" class="card compose">${csrf(s)}
        <input type="hidden" name="art" value="${esc(art)}"><input type="hidden" name="ref_ordner" value="${esc(v.refFolder)}"><input type="hidden" name="ref_uid" value="${esc(v.refUid)}">
        <input type="hidden" name="entwurf_ordner" value="${esc(v.draftFolder)}"><input type="hidden" name="entwurf_uid" value="${esc(v.draftUid)}">
        <input type="hidden" name="in_reply_to" value="${esc(v.inReplyTo)}"><input type="hidden" name="references" value="${esc(v.references)}">
        <input type="hidden" name="html" value="">
        <div class="cfields">
          <label>Von<select name="postfach">${options(accs.map(a => [a.id, `${smtpOf(a).fromName ? smtpOf(a).fromName + ' ' : ''}<${a.user}>`]), acc.id)}</select></label>
          <label>An<input name="an" value="${esc(v.to)}" maxlength="3000" autocomplete="off" placeholder="name@beispiel.de, …"></label>
          <label>Kopie (CC)<input name="cc" value="${esc(v.cc)}" maxlength="3000" autocomplete="off"></label>
          <details${v.bcc ? ' open' : ''}><summary class="small">Blindkopie (BCC)</summary><label class="nolabel"><input name="bcc" value="${esc(v.bcc)}" maxlength="3000" autocomplete="off" aria-label="Blindkopie"></label></details>
          <label>Betreff<input name="betreff" value="${esc(v.subject)}" maxlength="300"></label>
          <label>Signatur<select name="signatur"><option value="0">– keine –</option>${options(sigs.map(x => [x.id, x.name]), sig ? sig.id : 0)}</select> <a class="small" href="/signaturen">Signaturen bearbeiten</a></label>
        </div>
        ${toolbar()}
        <div class="editor" data-editor contenteditable="true" spellcheck="true" lang="de" aria-label="Text der Mail">${html}</div>
        <textarea name="text" rows="14" hidden aria-label="Text (nur Text)">${esc(v.text || '')}</textarea>
        <noscript><p class="muted small">Ohne JavaScript geht nur reiner Text – bitte „Nur Text“ ankreuzen.</p></noscript>
        <label class="check"><input type="checkbox" name="plain" value="1"${v.plain ? ' checked' : ''}> Nur Text (ohne Formatierung)</label>
        ${v.origAtts && v.origAtts.length ? `<fieldset><legend>Anhänge der ${art === 'entwurf' ? 'Mail' : 'Original-Mail'}</legend>${v.origAtts.map(a => `<label class="check"><input type="checkbox" name="orig_${a.i}" value="1" checked> ${esc(a.filename)}</label>`).join('')}</fieldset>` : ''}
        <label>Anhänge hinzufügen (zusammen höchstens 25 MB)<input type="file" name="anhang" multiple></label>
        <div class="row wrap"><button class="btn primary" name="aktion" value="senden">Senden</button><button class="btn" name="aktion" value="entwurf">Als Entwurf speichern</button>
          <a class="btn ghost" href="/post/${acc.id}">Verwerfen</a></div>
      </form>
      ${sigs.map(x => `<template id="sig-${x.id}">${x.html}</template>`).join('')}
      <script src="/editor.js" defer></script>`
    }))
  }

  app.get('/post/neu', async (req, res) => {
    const acc = getAccount(int(req.query.postfach, 1, 1e9, 0)) || listAccounts()[0]
    if (!acc) return back(res, '/einstellungen#postfaecher', { err: 'Bitte zuerst ein Postfach eintragen.' })
    const art = ['antwort', 'alle', 'weiter', 'entwurf'].includes(req.query.art) ? req.query.art : 'neu'
    try {
      const v = await prefill(req, acc, art, String(req.query.ordner || 'INBOX'), art === 'neu' ? 0 : int(req.query.uid, 1, 2 ** 32, 0))
      if (req.query.an && art === 'neu') v.to = String(req.query.an).slice(0, 300)
      renderCompose(req, res, acc, art, v, req.query.fehler)
    } catch (e) { back(res, `/post/${acc.id}`, { err: errText(e) }) }
  })

  // Formular mit Dateien einlesen (Grenzen: 20 Dateien, 25 MB zusammen)
  function readForm (req) {
    return new Promise((resolve, reject) => {
      const fields = {}; const files = []; let total = 0; let tooBig = false
      const bb = busboy({ headers: req.headers, defParamCharset: 'utf8', limits: { fileSize: MAX_TOTAL, files: 20, fields: 100, fieldSize: 20 * 1024 * 1024 } })
      bb.on('field', (k, val) => { fields[k] = val })
      bb.on('file', (name, stream, info) => {
        const chunks = []
        stream.on('data', (d) => { total += d.length; if (total > MAX_TOTAL) tooBig = true; else chunks.push(d) })
        stream.on('end', () => {
          if (stream.truncated) tooBig = true
          const buf = Buffer.concat(chunks)
          if (name === 'anhang' && info.filename && buf.length) files.push({ filename: String(info.filename).replace(/[\r\n\\/]+/g, '_').slice(0, 150), contentType: info.mimeType || 'application/octet-stream', content: buf })
        })
      })
      bb.on('error', reject)
      bb.on('close', () => resolve({ fields, files, tooBig }))
      req.pipe(bb)
    })
  }

  app.post('/post/senden', async (req, res) => {
    let form
    try { form = await readForm(req) } catch (e) { return res.status(400).send('Formular konnte nicht gelesen werden.') }
    const f = form.fields
    const ok = typeof f.csrf === 'string' && f.csrf.length === req.session.csrf.length && crypto.timingSafeEqual(Buffer.from(f.csrf), Buffer.from(req.session.csrf))
    if (!ok) return back(res, '/post', { err: 'Die Seite war veraltet – bitte noch einmal versuchen.' })
    const acc = getAccount(int(f.postfach, 1, 1e9, 0))
    if (!acc) return back(res, '/post', { err: 'Postfach nicht gefunden.' })
    const art = ['antwort', 'alle', 'weiter', 'entwurf'].includes(f.art) ? f.art : 'neu'
    const v = { to: f.an || '', cc: f.cc || '', bcc: f.bcc || '', subject: f.betreff || '', html: f.html || '', text: f.text || '', plain: f.plain === '1', signatur: f.signatur, keepSig: true,
      inReplyTo: f.in_reply_to || '', references: f.references || '', refFolder: f.ref_ordner || '', refUid: f.ref_uid || '', draftFolder: f.entwurf_ordner || '', draftUid: f.entwurf_uid || '', origAtts: [] }
    const again = (err) => renderCompose(req, res, acc, art, v, err)
    if (form.tooBig) return again('Die Anhänge sind zu groß (höchstens 25 MB zusammen) – bitte erneut auswählen.')
    try {
      // Anhänge der Original-Mail bzw. des Entwurfs (gefährliche nie)
      const atts = [...form.files]
      const folders = await listFolders(acc)
      if (v.refFolder && v.refUid && folders.some(x => x.path === v.refFolder) && (art === 'weiter' || art === 'entwurf')) {
        const msg = await readMessage(acc, v.refFolder, int(v.refUid, 1, 2 ** 32, 0), { markSeen: false })
        const orig = msg ? attachmentsOf(msg.parsed).filter(a => !(a.related && a.cid) && !a.danger) : []
        v.origAtts = orig
        for (const a of orig) if (f['orig_' + a.i] === '1') atts.push({ filename: a.filename, contentType: a.contentType, content: a.content })
      }
      const m = {
        to: parseRecipients(v.to), cc: parseRecipients(v.cc), bcc: parseRecipients(v.bcc), subject: v.subject,
        html: v.html, text: v.text, plain: v.plain, attachments: atts,
        inReplyTo: /^<[^<>\s]{3,400}>$/.test(v.inReplyTo) ? v.inReplyTo : undefined,
        references: v.references.split(/\s+/).filter(x => /^<[^<>\s]{3,400}>$/.test(x)).slice(-20).join(' ') || undefined,
        draft: v.draftFolder && v.draftUid && folders.some(x => x.path === v.draftFolder) ? { folder: v.draftFolder, uid: int(v.draftUid, 1, 2 ** 32, 0) } : null
      }
      if ((art === 'antwort' || art === 'alle' || art === 'weiter') && v.refFolder && folders.some(x => x.path === v.refFolder)) m.replyTo = { folder: v.refFolder, uid: int(v.refUid, 1, 2 ** 32, 0), forward: art === 'weiter' }
      if (f.aktion === 'entwurf') {
        const d = await saveDraft(acc, m)
        return back(res, `/post/${acc.id}?${q({ ordner: d.folder })}`, { msg: 'Entwurf gespeichert.' })
      }
      const r = await sendMessage(acc, m)
      back(res, `/post/${acc.id}${v.refFolder && art !== 'entwurf' ? '?' + q({ ordner: v.refFolder }) : ''}`, { msg: `Mail gesendet${r.sentCopy ? ` – Kopie in „${r.sentCopy}“` : ''}.` })
    } catch (e) {
      again((e.responseCode ? `Der Mailserver hat abgelehnt (${e.responseCode}): ` : '') + errText(e) + (form.files.length ? ' – Anhänge bitte erneut auswählen.' : ''))
    }
  })

  // ---------- Signaturen ----------
  app.get('/signaturen', (req, res) => {
    const s = req.session
    const sigs = listSignatures()
    const edit = req.query.neu ? { id: 0, name: '', html: '' } : (getSignature(int(req.query.bearbeiten, 0, 1e9, 0)) || null)
    const accs = listAccounts()
    res.set('Content-Security-Policy', EDITOR_CSP)
    res.send(page({
      title: 'Signaturen', session: s, path: '/post', ...flash(req),
      body: `<h1>Signaturen</h1>
      <section class="card"><h2>Deine Signaturen</h2>
        ${sigs.map(x => `<div class="sig-item"><div class="row between"><b>${esc(x.name)}</b><span class="row"><a class="btn sm" href="/signaturen?bearbeiten=${x.id}">Bearbeiten</a>
          <form method="post" action="/signaturen/${x.id}/loeschen" class="inline">${csrf(s)}<button class="btn sm ghost" data-confirm="Signatur „${esc(x.name)}“ löschen?">Löschen</button></form></span></div>
          <div class="sig-preview">${x.html}</div></div>`).join('') || '<p class="muted">Noch keine Signatur.</p>'}
        ${edit ? '' : '<a class="btn primary" href="/signaturen?neu=1">Neue Signatur</a>'}
      </section>
      ${edit ? `<section class="card"><h2>${edit.id ? 'Signatur bearbeiten' : 'Neue Signatur'}</h2>
        <form method="post" action="/signaturen" class="compose">${csrf(s)}<input type="hidden" name="id" value="${edit.id}"><input type="hidden" name="html" value="">
          <label>Name (nur für dich, z. B. „Flexisticker“ oder „Privat kurz“)<input name="name" value="${esc(edit.name)}" maxlength="60" required></label>
          ${toolbar()}
          <div class="editor small-ed" data-editor contenteditable="true" spellcheck="true" lang="de" aria-label="Signatur">${edit.html || '<p>Viele Grüße<br>Dein Name</p>'}</div>
          <p class="muted small">Logo: Knopf „Bild“ oder Bild hineinziehen – es wird mit der Mail verschickt (kommt auch an, wenn der Empfänger externe Bilder blockiert).</p>
          <div class="row"><button class="btn primary">Speichern</button><a class="btn ghost" href="/signaturen">Abbrechen</a></div>
        </form><script src="/editor.js" defer></script></section>` : ''}
      ${accs.length && sigs.length ? `<section class="card"><h2>Standard je Postfach</h2>
        <form method="post" action="/signaturen/standard" class="form">${csrf(s)}
          <div class="table-wrap"><table class="tbl"><thead><tr><th>Postfach</th><th>Neue Mail</th><th>Antworten/Weiterleiten</th></tr></thead><tbody>
          ${accs.map(a => `<tr><td>${esc(accountLabel(a))}<div class="muted small">${esc(a.user)}</div></td>
            <td><select name="neu_${a.id}"><option value="0">– keine –</option>${options(sigs.map(x => [x.id, x.name]), a.sig_new || 0)}</select></td>
            <td><select name="antwort_${a.id}"><option value="0">– keine –</option>${options(sigs.map(x => [x.id, x.name]), a.sig_reply || 0)}</select></td></tr>`).join('')}
          </tbody></table></div>
          <div class="row"><button class="btn primary">Speichern</button></div></form></section>` : ''}`
    }))
  })
  app.post('/signaturen', (req, res) => {
    try { saveSignature(int(req.body.id, 0, 1e9, 0), req.body.name, req.body.html); back(res, '/signaturen', { msg: 'Signatur gespeichert.' }) } catch (e) { back(res, '/signaturen', { err: errText(e) }) }
  })
  app.post('/signaturen/:id/loeschen', (req, res) => { deleteSignature(int(req.params.id, 1, 1e9, 0)); back(res, '/signaturen', { msg: 'Gelöscht.' }) })
  app.post('/signaturen/standard', (req, res) => {
    for (const a of listAccounts()) setDefaultSignatures(a.id, getSignature(req.body['neu_' + a.id]) ? req.body['neu_' + a.id] : 0, getSignature(req.body['antwort_' + a.id]) ? req.body['antwort_' + a.id] : 0)
    back(res, '/signaturen', { msg: 'Gespeichert.' })
  })
}
