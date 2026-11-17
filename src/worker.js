// Der eigentliche Durchlauf: Korrekturen erkennen → Posteingang einordnen → (scharf) verschieben.
import { db, now, kvGet, kvSet, log, prune } from './db.js'
import { getConfig, activeCategories, categoryById, isNight, targetLabel } from './config.js'
import { withClient, ensureFolders, categoryPath, pathString, readMessages, readIds, moveMessage, findByMsgId, listFolders } from './imap.js'
import { classify } from './classify.js'
import { recordCorrection, addExample, learnSender } from './learn.js'

const MAX_RUN_MS = 15 * 60 * 1000
const byMsgid = db.prepare('SELECT * FROM mails WHERE msgid = ?')
const byId = db.prepare('SELECT * FROM mails WHERE id = ?')

function upd (id, fields) {
  const keys = Object.keys(fields)
  db.prepare(`UPDATE mails SET ${keys.map(k => k + ' = ?').join(', ')}, updated_at = ? WHERE id = ?`).run(...keys.map(k => fields[k] ?? null), now(), id)
}

function insert (m, d, status, folder, uidvalidity) {
  const t = now()
  db.prepare(`INSERT INTO mails (msgid, from_addr, from_name, domain, subject, date, snippet, hints, folder, uid, uidvalidity,
    decision, source, confidence, reason, status, created_at, updated_at, moved_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(m.msgid, m.from_addr, m.from_name, m.domain, m.subject, m.date, m.snippet, m.hints, folder, m.uid, String(uidvalidity),
      d.decision, d.source, d.confidence ?? null, d.reason || '', status, t, t, null)
  return byMsgid.get(m.msgid)
}

function setStatus (patch) {
  kvSet('status', { ...kvGet('status', {}), ...patch })
}
export const getStatus = () => kvGet('status', {})

// Pfade aller Kategorien (Zeichenkette mit Trennzeichen des Servers)
function folderMap (client, cfg) {
  const map = {}
  for (const c of activeCategories(cfg)) map[c.id] = pathString(client, categoryPath(cfg, c))
  return map
}
const destPath = (map, target) => target === 'inbox' ? 'INBOX' : map[target]

// 1) Ordner „Sortiert/…“ beobachten: Was dort neu auftaucht und nicht von uns kommt, ist eine Korrektur bzw. selbst einsortiert.
async function watchFolders (client, cfg, map, existing, stats) {
  const watch = kvGet('watch', {})
  for (const [catId, path] of Object.entries(map)) {
    if (!existing.has(path)) continue
    const lock = await client.getMailboxLock(path)
    try {
      const mb = client.mailbox
      const uv = String(mb.uidValidity)
      const st = watch[path]
      if (!st || st.uidValidity !== uv) { // erstes Mal oder Ordner neu angelegt: nur Ausgangsstand merken
        watch[path] = { uidValidity: uv, lastUid: Math.max(0, Number(mb.uidNext) - 1) }
        continue
      }
      if (Number(mb.uidNext) - 1 <= st.lastUid) continue
      const found = await client.search({ uid: `${st.lastUid + 1}:*` }, { uid: true })
      const uids = (found || []).filter(u => u > st.lastUid).sort((a, b) => a - b).slice(0, 200)
      if (!uids.length) continue
      const ids = await readIds(client, uids)
      const unknown = []
      for (const x of ids) {
        const rec = byMsgid.get(x.msgid)
        if (!rec) { unknown.push(x.uid); continue }
        if (rec.decision === catId && rec.status === 'moved') { // eigene Verschiebung
          upd(rec.id, { folder: path, uid: x.uid, uidvalidity: uv })
          continue
        }
        recordCorrection(rec, catId, 'outlook')
        upd(rec.id, { folder: path, uid: x.uid, uidvalidity: uv, decision: catId, source: 'correction', status: 'moved', reason: 'von Hand einsortiert', moved_at: now() })
        stats.corrections++
      }
      // Mails, die der Sortierer nie gesehen hat und die von Hand hier einsortiert wurden → als Beispiel lernen
      for (let i = 0; i < unknown.length; i += 20) {
        for (const m of await readMessages(client, unknown.slice(i, i + 20))) {
          if (byMsgid.get(m.msgid)) continue
          addExample(m, catId, null, 'outlook')
          learnSender(m.from_addr, catId, 'outlook')
          insert(m, { decision: catId, source: 'manual', reason: 'von Hand einsortiert' }, 'moved', path, uv)
          stats.corrections++
        }
      }
      watch[path].lastUid = Math.max(st.lastUid, ...uids)
    } finally { lock.release() }
  }
  kvSet('watch', watch)
}

// 2) Posteingang: neue/unbekannte Mails einordnen (neueste zuerst), zurückgeschobene erkennen, im Scharf-Modus verschieben
async function processInbox (client, cfg, map, stats, started) {
  const lock = await client.getMailboxLock('INBOX')
  try {
    const mb = client.mailbox
    const uv = String(mb.uidValidity)
    let uids = []
    if (mb.exists > 0) {
      const q = cfg.backlog && Number(cfg.backlogMonths) > 0
        ? { since: new Date(Date.now() - Number(cfg.backlogMonths) * 30.5 * 864e5) }
        : { all: true }
      uids = (await client.search(q, { uid: true })) || []
    }
    // Ohne Altbestand: nur Mails, die nach dem ersten Start ankommen
    const base = kvGet('inboxBaseline', null)
    if (!base || base.uidValidity !== uv) kvSet('inboxBaseline', { uidValidity: uv, uid: Math.max(0, Number(mb.uidNext) - 1), at: now() })
    const baseline = kvGet('inboxBaseline').uid
    const known = new Set(db.prepare("SELECT uid FROM mails WHERE folder = 'INBOX' AND uidvalidity = ?").all(uv).map(r => r.uid))
    let todo = uids.filter(u => !known.has(u))
    if (!cfg.backlog) todo = todo.filter(u => u > baseline)
    todo.sort((a, b) => b - a)
    stats.left = todo.length
    const limit = isNight(cfg) ? Number(cfg.batchNight) || 300 : Number(cfg.batchDay) || 25
    todo = todo.slice(0, limit)

    for (let i = 0; i < todo.length; i += 10) {
      if (Date.now() - started > MAX_RUN_MS) break
      const chunk = await readMessages(client, todo.slice(i, i + 10))
      for (const m of chunk) {
        if (Date.now() - started > MAX_RUN_MS) break
        stats.left--
        const rec = byMsgid.get(m.msgid)
        if (rec) {
          if (rec.status === 'moved' && rec.folder && rec.folder !== 'INBOX' && rec.decision !== 'inbox') {
            // Michael hat die Mail zurück in den Posteingang gezogen → „gehört nicht dahin“
            recordCorrection(rec, 'inbox', 'outlook')
            upd(rec.id, { folder: 'INBOX', uid: m.uid, uidvalidity: uv, decision: 'inbox', source: 'correction', status: 'kept', reason: 'zurück in den Posteingang gezogen' })
            stats.corrections++
          } else {
            upd(rec.id, { folder: 'INBOX', uid: m.uid, uidvalidity: uv })
          }
          continue
        }
        const d = await classify(m, cfg) // Ollama-Fehler brechen den Durchlauf ab (wird beim nächsten Mal nachgeholt)
        stats.read++
        if (d.decision === 'inbox') { insert(m, d, 'kept', 'INBOX', uv); stats.kept++; continue }
        const r = insert(m, d, 'planned', 'INBOX', uv)
        if (cfg.mode === 'live') await moveRecord(client, r, map, uv, stats)
        else stats.planned++
      }
    }

    // Scharf: offene Vorschläge (z. B. aus dem Probelauf) jetzt ausführen
    if (cfg.mode === 'live') {
      const open = db.prepare("SELECT * FROM mails WHERE status = 'planned' AND folder = 'INBOX' AND uidvalidity = ? ORDER BY id DESC LIMIT ?").all(uv, limit * 2)
      for (const r of open) {
        if (Date.now() - started > MAX_RUN_MS) break
        await moveRecord(client, r, map, uv, stats)
      }
    }
  } finally { lock.release() }
}

async function moveRecord (client, r, map, uv, stats) {
  const dest = destPath(map, r.decision)
  if (!dest) { upd(r.id, { status: 'kept', reason: (r.reason || '') + ' (Ordner abgeschaltet)' }); return }
  try {
    const exists = await client.search({ uid: String(r.uid) }, { uid: true })
    if (!exists || !exists.length) { upd(r.id, { status: 'gone', error: 'nicht mehr im Posteingang' }); return }
    const newUid = await moveMessage(client, r.uid, dest)
    upd(r.id, { status: 'moved', folder: dest, uid: newUid, moved_at: now(), error: null })
    stats.moved++
  } catch (e) {
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
  const started = Date.now()
  const stats = { read: 0, planned: 0, moved: 0, kept: 0, corrections: 0, errors: 0, left: 0 }
  setStatus({ running: true, lastStart: now(), why })
  try {
    await withClient(cfg, async (client) => {
      const map = folderMap(client, cfg)
      let existing = new Set(await listFolders(client))
      if (cfg.mode === 'live') {
        const created = await ensureFolders(client, cfg, activeCategories(cfg))
        if (created.length) { log('info', 'Ordner angelegt: ' + created.join(', ')); existing = new Set(await listFolders(client)) }
      }
      await watchFolders(client, cfg, map, existing, stats)
      await processInbox(client, cfg, map, stats, started)
    })
    const msg = `Durchlauf (${why}): ${stats.read} gelesen, ${stats.moved} verschoben, ${stats.planned} im Probelauf vorgemerkt, ${stats.kept} bleiben im Posteingang, ${stats.corrections} Korrekturen erkannt` +
      (stats.errors ? `, ${stats.errors} Fehler` : '') + (stats.left > 0 ? `, ${stats.left} warten noch` : '')
    if (stats.read || stats.moved || stats.corrections || stats.errors) log(stats.errors ? 'warn' : 'info', msg)
    setStatus({ running: false, lastEnd: now(), lastOk: now(), lastError: null, last: stats, backlogLeft: Math.max(0, stats.left) })
  } catch (e) {
    const text = String((e && (e.responseText || e.message)) || e)
    log('error', `Durchlauf abgebrochen: ${text}` + (stats.read ? ` (vorher ${stats.read} Mails eingeordnet)` : ''))
    setStatus({ running: false, lastEnd: now(), lastError: text.slice(0, 400), last: stats })
  }
  prune()
  return stats
}

// ---- Aktionen aus der Oberfläche ----

// Korrektur: „Richtig wäre …“ – lernen und (wenn nötig) verschieben
export async function correct (id, target) {
  const cfg = getConfig()
  const rec = byId.get(id)
  if (!rec) throw new Error('Mail nicht gefunden')
  if (target !== 'inbox' && !categoryById(target, cfg)) throw new Error('Unbekannter Ordner')
  recordCorrection(rec, target, 'ui')
  const base = { decision: target, source: 'correction', reason: 'korrigiert', confidence: null, error: null }
  if (rec.status === 'gone') { upd(id, base); return }
  const inInbox = !rec.folder || rec.folder === 'INBOX'
  // Liegt noch im Posteingang und Probelauf (oder Ziel = Posteingang): nur vormerken
  if (inInbox && (cfg.mode !== 'live' || target === 'inbox')) {
    upd(id, { ...base, status: target === 'inbox' ? 'kept' : 'planned' })
    return
  }
  await withClient(cfg, async (client) => {
    await ensureFolders(client, cfg, activeCategories(cfg))
    const map = folderMap(client, cfg)
    const dest = destPath(map, target)
    const from = inInbox ? 'INBOX' : rec.folder
    if (from === dest) { upd(id, { ...base, status: target === 'inbox' ? 'kept' : 'moved' }); return }
    const lock = await client.getMailboxLock(from)
    try {
      let uid = rec.uid
      const ok = uid && (await client.search({ uid: String(uid) }, { uid: true }) || []).length
      if (!ok) uid = (await findByMsgId(client, rec.msgid))[0]
      if (!uid) throw new Error(`Mail liegt nicht mehr in „${from}“ – wurde sie in Outlook verschoben oder gelöscht?`)
      const newUid = await moveMessage(client, uid, dest)
      upd(id, { ...base, status: target === 'inbox' ? 'kept' : 'moved', folder: dest, uid: newUid, moved_at: now() })
    } finally { lock.release() }
  })
}

// Bestätigen: „passt“ – zählt für die Absender-Regel
export function confirm (id) {
  const rec = byId.get(id)
  if (!rec || !rec.decision) throw new Error('Mail nicht gefunden')
  recordCorrection(rec, rec.decision, 'ui')
  if (!String(rec.reason || '').endsWith('✓')) upd(id, { reason: (rec.reason || '') + ' ✓' })
}

// Rückgängig: zurück in den Posteingang (ohne zu lernen)
export async function undo (ids) {
  const cfg = getConfig()
  const recs = ids.map(id => byId.get(id)).filter(r => r && (r.status === 'moved' || r.status === 'planned'))
  if (!recs.length) return 0
  let done = 0
  const planned = recs.filter(r => r.status === 'planned')
  for (const r of planned) { upd(r.id, { status: 'undone', reason: (r.reason || '') + ' – verworfen' }); done++ }
  const moved = recs.filter(r => r.status === 'moved' && r.folder && r.folder !== 'INBOX')
  if (!moved.length) return done
  await withClient(cfg, async (client) => {
    const groups = new Map()
    for (const r of moved) { if (!groups.has(r.folder)) groups.set(r.folder, []); groups.get(r.folder).push(r) }
    for (const [folder, list] of groups) {
      let lock
      try { lock = await client.getMailboxLock(folder) } catch { for (const r of list) upd(r.id, { error: `Ordner „${folder}“ nicht gefunden` }); continue }
      try {
        for (const r of list) {
          let uid = r.uid
          const ok = uid && (await client.search({ uid: String(uid) }, { uid: true }) || []).length
          if (!ok) uid = (await findByMsgId(client, r.msgid))[0]
          if (!uid) { upd(r.id, { status: 'gone', error: 'nicht mehr im Ordner' }); continue }
          const newUid = await moveMessage(client, uid, 'INBOX')
          upd(r.id, { status: 'undone', folder: 'INBOX', uid: newUid, error: null })
          done++
        }
      } finally { lock.release() }
    }
  })
  log('info', `${done} Verschiebung(en) rückgängig gemacht`)
  return done
}

// Liegengebliebene (unsichere KI-Fälle) beim nächsten Durchlauf neu einordnen lassen
export function requeueKept () {
  const r = db.prepare("DELETE FROM mails WHERE status = 'kept' AND source = 'ki' AND folder = 'INBOX'").run()
  return Number(r.changes || 0)
}

export function decisionLabel (rec, cfg = getConfig()) {
  return targetLabel(rec.decision, cfg)
}

// Zeitplan
export function startScheduler () {
  setInterval(() => {
    const cfg = getConfig()
    if (cfg.paused || running) return
    if (!cfg.imap.host || !cfg.imap.user) return
    const st = getStatus()
    const last = st.lastStart ? Date.parse(st.lastStart) : 0
    if (Date.now() - last >= Math.max(1, Number(cfg.intervalMin) || 5) * 60000) runOnce('Zeitplan')
  }, 30000).unref()
}
