// Spam und „Achtung Verdacht“ aufräumen: nach X Tagen im Ordner in den Papierkorb des Postfachs (oder endgültig löschen).
// Standard aus. Gezählt wird ab dem Tag, an dem der Mail-Sortierer die Mail im Ordner zum ersten Mal gesehen hat –
// eine alte Mail, die gerade erst einsortiert wurde, bleibt also auch die volle Frist liegen. Mit Fähnchen markierte Mails bleiben immer.
import { db, now, kvGet, kvSet, log } from './db.js'
import { readIds } from './imap.js'

const DAY = 86400000
export const CLEAN_CATS = ['spam', 'verdacht']
const TRASH_NAMES = ['trash', 'papierkorb', 'gelöschte elemente', 'gelöschte objekte', 'deleted items', 'deleted messages', 'deleted']

export function cleanupCfg (cfg) {
  const c = cfg.cleanup || {}
  return {
    spam: Math.max(0, Number(c.spam) || 0),
    verdacht: Math.max(0, Number(c.verdacht) || 0),
    mode: c.mode === 'delete' ? 'delete' : 'trash'
  }
}

// Papierkorb des Postfachs finden (Sonderordner \Trash, sonst üblicher Name)
export async function findTrash (client) {
  const list = await client.list()
  const special = list.find(b => b.specialUse === '\\Trash')
  if (special) return special.path
  const byName = list.find(b => TRASH_NAMES.includes(String(b.name || '').toLowerCase()))
  return byName ? byName.path : null
}

// Wünsche „jetzt leeren“ aus der Oberfläche (werden im nächsten Durchlauf erledigt)
export function requestEmpty (accId, catId) {
  const all = kvGet('cleanupNow', {})
  all[accId] = [...new Set([...(all[accId] || []), catId])]
  kvSet('cleanupNow', all)
}
function takeRequests (accId) {
  const all = kvGet('cleanupNow', {})
  const list = all[accId] || []
  if (list.length) { delete all[accId]; kvSet('cleanupNow', all) }
  return list
}

export async function cleanupAccount (acc, client, cfg, map, existing, stats, label) {
  const cc = cleanupCfg(cfg)
  const forced = takeRequests(acc.id)
  const todo = CLEAN_CATS.filter(c => (cc[c] > 0 || forced.includes(c)) && map[c] && existing.has(map[c]))
  if (!todo.length) return
  const seenAll = kvGet('cleanupSeen', {})
  const seen = seenAll[acc.id] || {}
  let trash
  for (const catId of todo) {
    const path = map[catId]
    const lock = await client.getMailboxLock(path)
    let due = []
    try {
      const uv = String(client.mailbox.uidValidity)
      if (!seen[path] || seen[path].uv !== uv) seen[path] = { uv, first: {} }
      const first = seen[path].first
      const all = (await client.search({ all: true }, { uid: true })) || []
      const flagged = new Set((await client.search({ flagged: true }, { uid: true })) || [])
      const t = Date.now()
      const keep = {}
      for (const u of all) keep[u] = first[u] || t
      seen[path].first = keep
      const limit = forced.includes(catId) ? Infinity : t - cc[catId] * DAY
      due = all.filter(u => !flagged.has(u) && keep[u] <= limit).slice(0, 500)
      if (!due.length) continue
      // Datensätze vorher heraussuchen (Message-ID → Eintrag)
      const msgids = (await readIds(client, due)).map(x => x.msgid).filter(Boolean)
      let dest = null
      if (cc.mode === 'trash') {
        if (trash === undefined) trash = await findTrash(client)
        if (!trash) { log('warn', `${label}: kein Papierkorb gefunden – „${path}“ wird nicht aufgeräumt (oder „endgültig löschen“ wählen).`); continue }
        if (trash === path) continue
        dest = trash
        await client.messageMove(due.join(','), trash, { uid: true })
      } else {
        await client.messageDelete(due.join(','), { uid: true })
      }
      for (const u of due) delete seen[path].first[u]
      const upd = db.prepare("UPDATE mails SET status = 'deleted', folder = ?, uid = NULL, error = ?, updated_at = ? WHERE account_id = ? AND msgid = ?")
      const note = dest ? 'in den Papierkorb gelegt' : 'endgültig gelöscht'
      for (const id of msgids) upd.run(dest, note, now(), acc.id, id)
      stats.deleted = (stats.deleted || 0) + due.length
      log('info', `${label}: ${due.length} Mail(s) aus „${path}“ ${note}${forced.includes(catId) ? ' (von Hand geleert)' : ` (älter als ${cc[catId]} Tage im Ordner)`}`)
    } finally { lock.release() }
  }
  seenAll[acc.id] = seen
  kvSet('cleanupSeen', seenAll)
}
