// Der eigentliche Durchlauf je Postfach: Korrekturen erkennen → Posteingang einordnen → (scharf) verschieben.
// Danach: Scanner-Ordner. Rechnungen landen gesammelt im Sammel-Postfach (invoice.js).
import { db, now, kvGet, kvSet, log, prune } from './db.js'
import { getConfig, activeCategories, categoryById, isNight, targetLabel } from './config.js'
import { enabledAccounts, getAccount, accountLabel, migrateAccounts } from './accounts.js'
import { connect, withClient, ensureFolders, categoryPath, pathString, readMessages, readIds, moveMessage, findByMsgId, listFolders } from './imap.js'
import { classify } from './classify.js'
import { recordCorrection, addExample, learnSender, isTrusted, isKnown } from './learn.js'
import { phishCheck, brandList, blocklistCheck, senderIp, pdfRisk } from './security.js'
import { handleMailInvoice, processScans, collecting, dropForMail } from './invoice.js'
import { licensedFull } from './license.js'

const MAX_RUN_MS = 20 * 60 * 1000
const byMsgid = db.prepare('SELECT * FROM mails WHERE account_id = ? AND msgid = ?')
const byId = db.prepare('SELECT * FROM mails WHERE id = ?')

function upd (id, fields) {
  const keys = Object.keys(fields)
  db.prepare(`UPDATE mails SET ${keys.map(k => k + ' = ?').join(', ')}, updated_at = ? WHERE id = ?`).run(...keys.map(k => fields[k] ?? null), now(), id)
}

function insert (acc, m, d, status, folder, uidvalidity) {
  const t = now()
  db.prepare(`INSERT INTO mails (account_id, msgid, from_addr, from_name, domain, subject, date, snippet, hints, folder, uid, uidvalidity,
    decision, source, confidence, reason, status, created_at, updated_at, moved_at, risk, risk_reasons)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(acc.id, m.msgid, m.from_addr, m.from_name, m.domain, m.subject, m.date, m.snippet, m.hints, folder, m.uid, String(uidvalidity),
      d.decision, d.source, d.confidence ?? null, d.reason || '', status, t, t, null, d.risk ?? null, d.riskReasons ? JSON.stringify(d.riskReasons) : null)
  return byMsgid.get(acc.id, m.msgid)
}

export function setStatus (patch) { kvSet('status', { ...kvGet('status', {}), ...patch }) }
export const getStatus = () => kvGet('status', {})
function setAccStatus (id, patch) {
  const all = kvGet('accStatus', {})
  all[id] = { ...(all[id] || {}), ...patch }
  kvSet('accStatus', all)
}
export const getAccStatus = () => kvGet('accStatus', {})

function folderMap (client, cfg) {
  const map = {}
  for (const c of activeCategories(cfg)) map[c.id] = pathString(client, categoryPath(cfg, c))
  return map
}
const destPath = (map, target) => target === 'inbox' ? 'INBOX' : map[target]

// Verbindungen eines Durchlaufs (Sammel-Postfach wird nebenbei gebraucht)
function makeCtx () {
  const clients = new Map()
  return {
    async client (acc) {
      if (clients.has(acc.id)) return clients.get(acc.id)
      const c = connect(acc)
      c.on('error', () => {})
      await c.connect()
      clients.set(acc.id, c)
      return c
    },
    async close () { for (const c of clients.values()) await c.logout().catch(() => c.close()) }
  }
}

// 1) Ordner „Sortiert/…“ beobachten: Was dort neu auftaucht und nicht von uns kommt, ist eine Korrektur bzw. selbst einsortiert.
async function watchFolders (acc, client, map, existing, stats) {
  const all = kvGet('watch', {})
  const watch = all[acc.id] || {}
  for (const [catId, path] of Object.entries(map)) {
    if (!existing.has(path)) continue
    const lock = await client.getMailboxLock(path)
    try {
      const mb = client.mailbox
      const uv = String(mb.uidValidity)
      const st = watch[path]
      if (!st || st.uidValidity !== uv) { watch[path] = { uidValidity: uv, lastUid: Math.max(0, Number(mb.uidNext) - 1) }; continue }
      if (Number(mb.uidNext) - 1 <= st.lastUid) continue
      const found = await client.search({ uid: `${st.lastUid + 1}:*` }, { uid: true })
      const uids = (found || []).filter(u => u > st.lastUid).sort((a, b) => a - b).slice(0, 200)
      if (!uids.length) continue
      const ids = await readIds(client, uids)
      const unknown = []
      for (const x of ids) {
        const rec = byMsgid.get(acc.id, x.msgid)
        if (!rec) { unknown.push(x.uid); continue }
        if (rec.decision === catId && rec.status === 'moved') { upd(rec.id, { folder: path, uid: x.uid, uidvalidity: uv }); continue }
        recordCorrection(rec, catId, 'outlook')
        upd(rec.id, { folder: path, uid: x.uid, uidvalidity: uv, decision: catId, source: 'correction', status: 'moved', reason: 'von Hand einsortiert', moved_at: now() })
        stats.corrections++
      }
      for (let i = 0; i < unknown.length; i += 20) {
        for (const m of await readMessages(client, unknown.slice(i, i + 20))) {
          if (byMsgid.get(acc.id, m.msgid)) continue
          addExample(m, catId, null, 'outlook')
          learnSender(m.from_addr, catId, 'outlook')
          insert(acc, m, { decision: catId, source: 'manual', reason: 'von Hand einsortiert' }, 'moved', path, uv)
          stats.corrections++
        }
      }
      watch[path].lastUid = Math.max(st.lastUid, ...uids)
    } finally { lock.release() }
  }
  all[acc.id] = watch
  kvSet('watch', all)
}

// 2) Posteingang: unbekannte Mails einordnen (neueste zuerst), zurückgeschobene erkennen, im Scharf-Modus verschieben
async function processInbox (ctx, acc, client, cfg, map, stats, started, budget) {
  const lock = await client.getMailboxLock('INBOX')
  try {
    const mb = client.mailbox
    const uv = String(mb.uidValidity)
    let uids = []
    if (mb.exists > 0) {
      const q = cfg.backlog && Number(cfg.backlogMonths) > 0 ? { since: new Date(Date.now() - Number(cfg.backlogMonths) * 30.5 * 864e5) } : { all: true }
      uids = (await client.search(q, { uid: true })) || []
    }
    const bases = kvGet('inboxBaseline', {})
    if (!bases[acc.id] || bases[acc.id].uidValidity !== uv) { bases[acc.id] = { uidValidity: uv, uid: Math.max(0, Number(mb.uidNext) - 1), at: now() }; kvSet('inboxBaseline', bases) }
    const baseline = bases[acc.id].uid
    const known = new Set(db.prepare("SELECT uid FROM mails WHERE account_id = ? AND folder = 'INBOX' AND uidvalidity = ?").all(acc.id, uv).map(r => r.uid))
    let todo = uids.filter(u => !known.has(u))
    if (!cfg.backlog) todo = todo.filter(u => u > baseline)
    todo.sort((a, b) => b - a)
    let left = todo.length
    todo = todo.slice(0, budget)

    for (let i = 0; i < todo.length; i += 10) {
      if (Date.now() - started > MAX_RUN_MS) break
      for (const m of await readMessages(client, todo.slice(i, i + 10))) {
        if (Date.now() - started > MAX_RUN_MS) break
        left--
        const rec = byMsgid.get(acc.id, m.msgid)
        if (rec) {
          if (rec.status === 'moved' && rec.folder && rec.folder !== 'INBOX' && rec.decision !== 'inbox') {
            recordCorrection(rec, 'inbox', 'outlook')
            upd(rec.id, { folder: 'INBOX', uid: m.uid, uidvalidity: uv, decision: 'inbox', source: 'correction', status: 'kept', reason: 'zurück in den Posteingang gezogen' })
            await dropForMail(rec.id).catch(e => log('warn', 'Rechnung zurücksetzen: ' + e.message))
            stats.corrections++
          } else {
            upd(rec.id, { folder: 'INBOX', uid: m.uid, uidvalidity: uv })
          }
          continue
        }
        const d = await assess(m, cfg, stats)
        stats.read++
        if (d.decision === 'inbox') { insert(acc, m, d, 'kept', 'INBOX', uv); stats.kept++; continue }
        const r = insert(acc, m, d, 'planned', 'INBOX', uv)
        if (acc.mode === 'live') await moveRecord(ctx, acc, client, r, map, stats)
        else stats.planned++
      }
    }

    if (acc.mode === 'live') {
      const open = db.prepare("SELECT * FROM mails WHERE account_id = ? AND status = 'planned' AND folder = 'INBOX' AND uidvalidity = ? ORDER BY id DESC LIMIT ?").all(acc.id, uv, budget * 2)
      for (const r of open) {
        if (Date.now() - started > MAX_RUN_MS) break
        await moveRecord(ctx, acc, client, r, map, stats)
      }
    }
    return Math.max(0, left)
  } finally { lock.release() }
}

// Sicherheitsprüfung → Spam/Verdacht, sonst normale Einordnung (Regeln, Kontakte, KI)
async function assess (m, cfg, stats) {
  const sec = cfg.security
  const trusted = isTrusted(m)
  const known = isKnown(m)
  const atts = m._attachments || []
  const res = phishCheck({ ...m, text: m._text, html: m._html, headers: m._headers, attachments: atts }, { brands: brandList(sec.brands), trusted, known })
  // PDFs mit Skripten o. Ä. (soweit schon geladen)
  for (const a of atts) {
    if (/\.pdf$/i.test(a.filename) && a.content && a.content.length > 0 && a.content.subarray(0, 5).toString('latin1') === '%PDF-') {
      const r = pdfRisk(a.content).filter(x => x !== 'keine gültige PDF-Datei')
      if (r.length) { res.reasons.push({ p: 60, t: `PDF „${a.filename}“ ${r.join(', ')}` }); if (!trusted) res.score += 60; res.dangerous = true }
    }
  }
  let spam = false
  if (sec.spamHeader && res.spamHeader && !trusted && !known) spam = true
  if (sec.dnsbl && !trusted && !known) {
    try {
      const bl = await blocklistCheck({ ip: senderIp(m._headers), domains: [m.domain, ...(res.linkHosts || [])] }, sec)
      if (bl.hits.length) { spam = true; for (const h of bl.hits) res.reasons.push({ p: 20, t: h }); res.score += 20 * bl.hits.length }
      if (bl.warning && stats) stats.dnsWarning = bl.warning
    } catch { /* Sperrliste nicht erreichbar → ohne */ }
  }
  const reasons = res.reasons.slice(0, 8).map(r => r.t)
  const top = reasons.slice(0, 3).join('; ')
  if ((res.dangerous && sec.blockDangerous) || res.score >= Number(sec.phishThreshold || 60)) {
    if (stats) stats.suspicious = (stats.suspicious || 0) + 1
    return { decision: 'verdacht', source: 'security', confidence: Math.min(100, res.score), reason: top || 'verdächtig', risk: res.score, riskReasons: reasons }
  }
  if (spam) {
    if (stats) stats.spam = (stats.spam || 0) + 1
    return { decision: 'spam', source: 'security', confidence: Math.min(100, res.score), reason: top || 'Spam', risk: res.score, riskReasons: reasons }
  }
  const d = await classify(m, cfg)
  if (!trusted && d.suspicion >= 80) {
    res.score += 25; reasons.push(`KI hält die Mail für Betrug (${d.suspicion} %)`)
    if (res.score >= Number(sec.phishThreshold || 60)) {
      if (stats) stats.suspicious = (stats.suspicious || 0) + 1
      return { decision: 'verdacht', source: 'security', confidence: Math.min(100, res.score), reason: reasons.slice(0, 3).join('; '), risk: res.score, riskReasons: reasons }
    }
  }
  return { ...d, risk: res.score, riskReasons: res.score >= Number(sec.warnThreshold || 30) ? reasons : null }
}

async function moveRecord (ctx, acc, client, r, map, stats) {
  const dest = destPath(map, r.decision)
  if (!dest) { upd(r.id, { status: 'kept', reason: (r.reason || '') + ' (Ordner abgeschaltet)' }); return }
  try {
    const exists = await client.search({ uid: String(r.uid) }, { uid: true })
    if (!exists || !exists.length) { upd(r.id, { status: 'gone', error: 'nicht mehr im Posteingang' }); return }
    if (r.decision === 'rechnungen' && collecting()) {
      const placed = await handleMailInvoice(ctx, acc, r, client)
      if (placed && placed.blocked) {
        const v = map.verdacht
        const newUid = await moveMessage(client, r.uid, v)
        upd(r.id, { status: 'moved', decision: 'verdacht', source: 'security', folder: v, uid: newUid, moved_at: now(), reason: placed.blocked, risk: 80, risk_reasons: JSON.stringify([placed.blocked]) })
        stats.moved++; stats.suspicious = (stats.suspicious || 0) + 1
        return
      }
      if (placed) { upd(r.id, { status: 'moved', folder: placed.folder, uid: placed.uid, moved_at: now(), error: null }); stats.moved++; stats.invoices++; return }
      if (db.prepare('SELECT 1 FROM invoices WHERE mail_id = ?').get(r.id)) stats.invoices++
    }
    const newUid = await moveMessage(client, r.uid, dest)
    upd(r.id, { status: 'moved', folder: dest, uid: newUid, moved_at: now(), error: null })
    stats.moved++
  } catch (e) {
    if (/Ollama/.test(e.message)) throw e
    upd(r.id, { status: 'error', error: String(e.message || e).slice(0, 300) })
    stats.errors++
  }
}

let running = null
export function runOnce (why = 'Zeitplan') {
  if (running) return running
  running = run(why).finally(() => { running = null })
  return running
}
export const isRunning = () => !!running

async function run (why) {
  const cfg = getConfig()
  migrateAccounts(cfg)
  const started = Date.now()
  const total = { read: 0, planned: 0, moved: 0, kept: 0, corrections: 0, errors: 0, invoices: 0, scans: 0, left: 0 }
  setStatus({ running: true, lastStart: now(), why })
  const ctx = makeCtx()
  let failed = null
  try {
    // Ohne gültige Lizenz nur Probelauf: nichts wird verschoben oder abgelegt
    const full = licensedFull()
    const accounts = enabledAccounts().map(a => full ? a : { ...a, mode: 'probe' })
    let budget = isNight(cfg) ? Number(cfg.batchNight) || 300 : Number(cfg.batchDay) || 25
    for (const acc of accounts) {
      if (Date.now() - started > MAX_RUN_MS) break
      const stats = { read: 0, planned: 0, moved: 0, kept: 0, corrections: 0, errors: 0, invoices: 0 }
      try {
        const client = await ctx.client(acc)
        const map = folderMap(client, cfg)
        let existing = new Set(await listFolders(client))
        if (acc.mode === 'live') {
          const created = await ensureFolders(client, cfg, activeCategories(cfg))
          if (created.length) { log('info', `${accountLabel(acc)}: Ordner angelegt: ${created.join(', ')}`); existing = new Set(await listFolders(client)) }
        }
        await watchFolders(acc, client, map, existing, stats)
        const left = await processInbox(ctx, acc, client, cfg, map, stats, started, Math.max(5, budget))
        budget = Math.max(5, budget - stats.read)
        setAccStatus(acc.id, { lastOk: now(), lastError: null, left, last: stats })
        total.left += left
      } catch (e) {
        const text = String((e && (e.responseText || e.message)) || e)
        setAccStatus(acc.id, { lastError: text.slice(0, 300), lastErrorAt: now() })
        log('error', `${accountLabel(acc)}: ${e.authenticationFailed ? 'Anmeldung fehlgeschlagen (Benutzer/Passwort)' : text}`)
        if (/Ollama/.test(text)) { failed = text; break } // KI weg → später weiter
      }
      for (const k of Object.keys(stats)) if (typeof stats[k] === 'number') total[k] = (total[k] || 0) + stats[k]
      if (stats.dnsWarning) total.dnsWarning = stats.dnsWarning
    }
    if (!failed && full) {
      try { await processScans(ctx, total) } catch (e) { failed = 'Scanner: ' + e.message; log('error', failed) }
    }
    const msg = `Durchlauf (${why}): ${total.read} gelesen, ${total.moved} verschoben, ${total.planned} im Probelauf vorgemerkt, ${total.kept} bleiben im Posteingang, ${total.corrections} Korrekturen` +
      (total.invoices ? `, ${total.invoices} Rechnungen` : '') + (total.suspicious ? `, ${total.suspicious} verdächtig` : '') + (total.spam ? `, ${total.spam} Spam` : '') + (total.scans ? `, ${total.scans} Scans` : '') + (total.errors ? `, ${total.errors} Fehler` : '') + (total.left > 0 ? `, ${total.left} warten noch` : '')
    if (total.read || total.moved || total.corrections || total.errors || total.scans) log(total.errors ? 'warn' : 'info', msg)
    setStatus({ running: false, lastEnd: now(), lastOk: failed ? undefined : now(), lastError: failed || total.scanError || null, dnsWarning: total.dnsWarning || null, last: total, backlogLeft: total.left })
  } catch (e) {
    const text = String((e && (e.responseText || e.message)) || e)
    log('error', `Durchlauf abgebrochen: ${text}`)
    setStatus({ running: false, lastEnd: now(), lastError: text.slice(0, 400), last: total })
  } finally {
    await ctx.close()
  }
  prune()
  return total
}

// ---- Aktionen aus der Oberfläche ----

export async function correct (id, target) {
  const cfg = getConfig()
  const rec = byId.get(id)
  if (!rec) throw new Error('Mail nicht gefunden')
  if (target !== 'inbox' && !categoryById(target, cfg)) throw new Error('Unbekannter Ordner')
  const acc0 = getAccount(rec.account_id)
  if (!acc0) throw new Error('Postfach gibt es nicht mehr')
  const acc = licensedFull() ? acc0 : { ...acc0, mode: 'probe' }
  recordCorrection(rec, target, 'ui')
  if (rec.decision === 'rechnungen' && target !== 'rechnungen') await dropForMail(rec.id)
  const base = { decision: target, source: 'correction', reason: 'korrigiert', confidence: null, error: null }
  if (rec.status === 'gone') { upd(id, base); return }
  const inInbox = !rec.folder || rec.folder === 'INBOX'
  if (inInbox && (acc.mode !== 'live' || target === 'inbox')) { upd(id, { ...base, status: target === 'inbox' ? 'kept' : 'planned' }); return }
  if (inInbox && target === 'rechnungen' && collecting()) { upd(id, { ...base, status: 'planned' }); return } // nächster Durchlauf legt die Rechnung ab
  await withClient(acc, async (client) => {
    await ensureFolders(client, cfg, activeCategories(cfg))
    const map = folderMap(client, cfg)
    const dest = destPath(map, target)
    const from = inInbox ? 'INBOX' : rec.folder
    if (from === dest) { upd(id, { ...base, status: target === 'inbox' ? 'kept' : 'moved' }); return }
    const lock = await client.getMailboxLock(from)
    try {
      let uid = rec.uid
      const ok = uid && ((await client.search({ uid: String(uid) }, { uid: true })) || []).length
      if (!ok) uid = (await findByMsgId(client, rec.msgid))[0]
      if (!uid) throw new Error(`Mail liegt nicht mehr in „${from}“ – wurde sie in Outlook verschoben oder gelöscht?`)
      const newUid = await moveMessage(client, uid, dest)
      upd(id, { ...base, status: target === 'inbox' ? 'kept' : 'moved', folder: dest, uid: newUid, moved_at: now() })
    } finally { lock.release() }
  })
}

export function confirm (id) {
  const rec = byId.get(id)
  if (!rec || !rec.decision) throw new Error('Mail nicht gefunden')
  recordCorrection(rec, rec.decision, 'ui')
  if (!String(rec.reason || '').endsWith('✓')) upd(id, { reason: (rec.reason || '') + ' ✓' })
}

export async function undo (ids) {
  const recs = ids.map(id => byId.get(id)).filter(r => r && (r.status === 'moved' || r.status === 'planned'))
  let done = 0
  for (const r of recs.filter(r => r.status === 'planned')) { upd(r.id, { status: 'undone', reason: (r.reason || '') + ' – verworfen' }); done++ }
  const moved = recs.filter(r => r.status === 'moved' && r.folder && r.folder !== 'INBOX')
  const byAcc = new Map()
  for (const r of moved) { if (!byAcc.has(r.account_id)) byAcc.set(r.account_id, []); byAcc.get(r.account_id).push(r) }
  for (const [accId, list] of byAcc) {
    const acc = getAccount(accId)
    if (!acc) continue
    await withClient(acc, async (client) => {
      const groups = new Map()
      for (const r of list) { if (!groups.has(r.folder)) groups.set(r.folder, []); groups.get(r.folder).push(r) }
      for (const [folder, items] of groups) {
        let lock
        try { lock = await client.getMailboxLock(folder) } catch { for (const r of items) upd(r.id, { error: `Ordner „${folder}“ nicht gefunden` }); continue }
        try {
          for (const r of items) {
            let uid = r.uid
            const ok = uid && ((await client.search({ uid: String(uid) }, { uid: true })) || []).length
            if (!ok) uid = (await findByMsgId(client, r.msgid))[0]
            if (!uid) { upd(r.id, { status: 'gone', error: 'nicht mehr im Ordner' }); continue }
            const newUid = await moveMessage(client, uid, 'INBOX')
            upd(r.id, { status: 'undone', folder: 'INBOX', uid: newUid, error: null })
            if (r.decision === 'rechnungen') db.prepare("UPDATE invoices SET status = 'noinvoice', hint = 'Verschiebung rückgängig gemacht', updated_at = ? WHERE mail_id = ? AND same_message = 1 AND status = 'open'").run(now(), r.id)
            done++
          }
        } finally { lock.release() }
      }
    })
  }
  if (done) log('info', `${done} Verschiebung(en) rückgängig gemacht`)
  return done
}

export function requeueKept () {
  const r = db.prepare("DELETE FROM mails WHERE status = 'kept' AND source = 'ki' AND folder = 'INBOX'").run()
  return Number(r.changes || 0)
}

export function startScheduler () {
  migrateAccounts(getConfig())
  setInterval(() => {
    const cfg = getConfig()
    if (cfg.paused || running) return
    if (!enabledAccounts().length) return
    const st = getStatus()
    const last = st.lastStart ? Date.parse(st.lastStart) : 0
    if (Date.now() - last >= Math.max(1, Number(cfg.intervalMin) || 5) * 60000) runOnce('Zeitplan')
  }, 30000).unref()
}
