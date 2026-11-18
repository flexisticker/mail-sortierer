// Postfächer verwalten. Passwort je Postfach verschlüsselt (secrets.js, Name imap:<id>).
import { db, now, kvGet, kvSet } from './db.js'
import { getSecret, setSecret, hasSecret } from './secrets.js'

export const listAccounts = () => db.prepare('SELECT * FROM accounts ORDER BY id').all()
export const enabledAccounts = () => db.prepare('SELECT * FROM accounts WHERE enabled = 1 ORDER BY id').all()
export const getAccount = (id) => db.prepare('SELECT * FROM accounts WHERE id = ?').get(Number(id))
export const accountPassword = (a) => getSecret('imap:' + a.id)
export const accountHasPassword = (a) => hasSecret('imap:' + a.id)
export const accountLabel = (a) => a ? (a.name || a.user) : '?'

export function saveAccount (data, password) {
  const t = now()
  const v = {
    name: String(data.name || data.user || '').trim().slice(0, 80),
    host: String(data.host || '').trim().replace(/^imaps?:\/\//, '').slice(0, 200),
    port: Math.min(65535, Math.max(1, Number(data.port) || 993)),
    secure: data.secure ? 1 : 0,
    user: String(data.user || '').trim().slice(0, 200),
    allow_self_signed: data.allowSelfSigned ? 1 : 0,
    enabled: data.enabled === false ? 0 : 1
  }
  if (!v.host || !v.user) throw new Error('Server und Benutzer fehlen.')
  let id = Number(data.id) || 0
  if (id && getAccount(id)) {
    db.prepare('UPDATE accounts SET name = ?, host = ?, port = ?, secure = ?, user = ?, allow_self_signed = ?, enabled = ? WHERE id = ?')
      .run(v.name, v.host, v.port, v.secure, v.user, v.allow_self_signed, v.enabled, id)
  } else {
    if (db.prepare('SELECT 1 FROM accounts WHERE lower(user) = lower(?) AND lower(host) = lower(?)').get(v.user, v.host)) throw new Error('Dieses Postfach ist schon eingetragen.')
    id = Number(db.prepare("INSERT INTO accounts (name, host, port, secure, user, allow_self_signed, enabled, mode, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, 'probe', ?)")
      .run(v.name, v.host, v.port, v.secure, v.user, v.allow_self_signed, v.enabled, t).lastInsertRowid)
  }
  if (password) setSecret('imap:' + id, String(password).slice(0, 500))
  return getAccount(id)
}

// ---------- Postausgang (SMTP) für das Webmail ----------
/** Vorschlag für den Postausgangsserver: imap.x.de → smtp.x.de, sonst derselbe Server */
export const smtpGuess = (a) => String(a.host || '').replace(/^imap\./i, 'smtp.')
export function smtpOf (a) {
  return {
    host: a.smtp_host || smtpGuess(a),
    port: Number(a.smtp_port) || 465,
    secure: a.smtp_port ? !!a.smtp_secure : true,
    user: a.smtp_user || a.user,
    same: a.smtp_same !== 0,
    fromName: a.from_name || '',
    pass: a.smtp_same !== 0 ? getSecret('imap:' + a.id) : getSecret('smtp:' + a.id)
  }
}
export function saveSmtp (id, data, password) {
  const a = getAccount(id)
  if (!a) throw new Error('Postfach nicht gefunden.')
  const host = String(data.host || '').trim().replace(/^smtps?:\/\//, '').slice(0, 200)
  if (host && !/^[a-z0-9.-]+$/i.test(host)) throw new Error('Postausgangsserver ungültig.')
  db.prepare('UPDATE accounts SET smtp_host = ?, smtp_port = ?, smtp_secure = ?, smtp_user = ?, smtp_same = ?, from_name = ? WHERE id = ?')
    .run(host || null, Math.min(65535, Math.max(1, Number(data.port) || 465)), data.secure ? 1 : 0, String(data.user || '').trim().slice(0, 200) || null,
      data.same ? 1 : 0, String(data.fromName || '').replace(/[\r\n<>"]/g, '').trim().slice(0, 80) || null, a.id)
  if (!data.same && password) setSecret('smtp:' + a.id, String(password).slice(0, 500))
  return getAccount(a.id)
}
export function setDefaultSignatures (id, sigNew, sigReply) {
  db.prepare('UPDATE accounts SET sig_new = ?, sig_reply = ? WHERE id = ?').run(Number(sigNew) || null, Number(sigReply) || null, Number(id))
}

export function setAccountMode (id, mode) {
  db.prepare('UPDATE accounts SET mode = ? WHERE id = ?').run(mode === 'live' ? 'live' : 'probe', Number(id))
}

export function deleteAccount (id) {
  db.prepare('DELETE FROM accounts WHERE id = ?').run(Number(id))
  setSecret('imap:' + id, '')
  setSecret('smtp:' + id, '')
  const watch = kvGet('watch', {}); delete watch[id]; kvSet('watch', watch)
  const base = kvGet('inboxBaseline', {}); delete base[id]; kvSet('inboxBaseline', base)
}

// Umzug von 1.0: Postfach aus den Einstellungen wird Postfach Nr. 1
export function migrateAccounts (cfg) {
  if (listAccounts().length || !cfg.imap || !cfg.imap.host || !cfg.imap.user) return
  db.prepare("INSERT INTO accounts (id, name, host, port, secure, user, allow_self_signed, enabled, mode, created_at) VALUES (1, ?, ?, ?, ?, ?, ?, 1, ?, ?)")
    .run(cfg.imap.user, cfg.imap.host, Number(cfg.imap.port) || 993, cfg.imap.secure === false ? 0 : 1, cfg.imap.user, cfg.imap.allowSelfSigned ? 1 : 0, cfg.mode === 'live' ? 'live' : 'probe', now())
  const pw = getSecret('imapPassword')
  if (pw) { setSecret('imap:1', pw); setSecret('imapPassword', '') }
  // Beobachtungs-Stand pro Postfach ablegen
  const watch = kvGet('watch', {})
  if (watch && !watch[1] && Object.keys(watch).some(k => isNaN(Number(k)))) kvSet('watch', { 1: watch })
  const base = kvGet('inboxBaseline', null)
  if (base && base.uidValidity) kvSet('inboxBaseline', { 1: base })
}
