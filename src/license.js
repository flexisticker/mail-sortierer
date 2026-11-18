// Lizenz über die Vedly-Zentrale (Modul „mailsort“). Gleiches Verfahren wie in Vedly: signierte Lizenz (Ed25519),
// Online-Aktivierung mit dem Vedly-Lizenzschlüssel, Erneuerung alle 7 Tage, ohne Verbindung mind. 90 Tage weiter („Lease“).
// Ohne gültige Lizenz (nach 30 Tagen Test): nur noch Probelauf – nichts wird verschoben, nichts an Lexware geschickt.
// Installationen, die es schon vor 1.5.0 gab, gelten als Eigeninstallation und laufen ohne Lizenz.
import crypto from 'node:crypto'
import { sysdb as db, sysGet as kvGet, sysSet as kvSet, sysLog as log } from './db.js'
import { TRUSTED_KEYS } from './license-keys.js'

export const PRODUCT = 'mailsort'
export const DEFAULT_SERVER = 'https://lizenz.vedly.de'
const TRIAL_DAYS = 30
const CHECK_DAYS = 7
const WARN_DAYS = 14
const DAY = 864e5
const VERSION = process.env.APP_VERSION || ''

;(function init () {
  if (kvGet('installId')) return
  const users = db.prepare('SELECT COUNT(*) AS n FROM users').get().n
  kvSet('installId', crypto.randomUUID())
  kvSet('installFirstStart', new Date().toISOString())
  if (users > 0) kvSet('licenseExempt', { at: new Date().toISOString(), reason: 'Bestand vor 1.5.0' })
})()

export const installId = () => kvGet('installId')
export const isExempt = () => !!kvGet('licenseExempt')

function keys () {
  const list = [...TRUSTED_KEYS]
  if (process.env.NODE_ENV !== 'production' && process.env.LICENSE_DEV_PUBKEY) list.push(process.env.LICENSE_DEV_PUBKEY.replace(/\\n/g, '\n'))
  return list
}

export function verifyLicense (text) {
  const [p, s, extra] = String(text || '').trim().split('.')
  if (!p || !s || extra !== undefined) return null
  let ok = false
  for (const k of keys()) {
    try { if (crypto.verify(null, Buffer.from(p), k, Buffer.from(s, 'base64url'))) { ok = true; break } } catch { /* falscher Schlüssel */ }
  }
  if (!ok) return null
  try {
    const lic = JSON.parse(Buffer.from(p, 'base64url').toString('utf8'))
    return lic && lic.v === 1 && lic.id ? lic : null
  } catch { return null }
}

const de = (iso) => (iso ? new Date(iso).toLocaleDateString('de-DE', { timeZone: 'Europe/Berlin' }) : '')
const daysUntil = (iso) => Math.floor((Date.parse(iso) - Date.now()) / DAY)

/** state: exempt | trial | active | trialover | expired | lease | revoked | invalid | nomodule | released; full = alles erlaubt */
export function licenseState () {
  const exempt = isExempt()
  const stored = kvGet('license')
  const lic = stored ? verifyLicense(stored.text) : null
  const out = { installId: installId(), exempt, state: 'trial', full: true, message: '', warn: false, license: null, check: kvGet('licenseCheck', null) }
  if (exempt) { out.state = 'exempt'; return out }
  if (lic) {
    out.license = { id: lic.id, company: lic.company || '', validUntil: lic.validUntil || null, leaseUntil: lic.leaseUntil || null, keyHint: lic.keyHint || '' }
    const revoked = kvGet('licenseRevoked')
    let problem = null
    if (lic.installId !== out.installId) problem = ['invalid', 'Die Lizenz gehört zu einer anderen Installation. Bitte neu aktivieren.']
    else if (lic.product && lic.product !== PRODUCT) problem = ['invalid', 'Diese Lizenz ist nicht für den Mail-Sortierer ausgestellt.']
    else if (Array.isArray(lic.modules) && !lic.modules.includes(PRODUCT)) problem = ['nomodule', 'Die Vedly-Lizenz enthält den Mail-Sortierer nicht.']
    else if (revoked && revoked.licenseId === lic.id) problem = ['revoked', `Die Lizenz wurde gesperrt${revoked.reason ? ` (${revoked.reason})` : ''}.`]
    else if (lic.validUntil && Date.parse(lic.validUntil) + DAY <= Date.now()) problem = ['expired', `Die Lizenz ist am ${de(lic.validUntil)} abgelaufen.`]
    else if (lic.leaseUntil && Date.parse(lic.leaseUntil) <= Date.now()) problem = ['lease', 'Die Lizenz konnte zu lange nicht bei der Vedly-Zentrale bestätigt werden – Internetverbindung prüfen.']
    if (problem) return Object.assign(out, { state: problem[0], full: false, message: problem[1] + ' Bis dahin nur Probelauf.' })
    out.state = 'active'
    const valid = lic.validUntil ? daysUntil(lic.validUntil) + 1 : 999
    const lease = lic.leaseUntil ? daysUntil(lic.leaseUntil) : 999
    if (valid <= WARN_DAYS) Object.assign(out, { warn: true, message: `Die Lizenz läuft in ${Math.max(0, valid)} Tagen ab (${de(lic.validUntil)}).` })
    else if (lease <= WARN_DAYS) Object.assign(out, { warn: true, message: `Lizenz seit längerem nicht bestätigt – in ${Math.max(0, lease)} Tagen nur noch Probelauf.` })
    return out
  }
  if (kvGet('licenseReleased')) return Object.assign(out, { state: 'released', full: false, message: 'Die Lizenz wurde für diese Installation freigegeben. Bitte erneut aktivieren – bis dahin nur Probelauf.' })
  const first = Date.parse(kvGet('installFirstStart') || new Date().toISOString())
  const left = Math.ceil((first + TRIAL_DAYS * DAY - Date.now()) / DAY)
  out.trialLeft = Math.max(0, left)
  if (left > 0) return Object.assign(out, { state: 'trial', warn: true, message: `Testzeitraum: noch ${left} Tage. Danach Vedly-Lizenz mit dem Modul „Mail-Sortierer“ aktivieren.` })
  return Object.assign(out, { state: 'trialover', full: false, message: 'Der Testzeitraum ist abgelaufen – bitte Vedly-Lizenz aktivieren. Bis dahin nur Probelauf (nichts wird verschoben).' })
}

/** Darf scharf verschoben / an Lexware geschickt werden? */
export const licensedFull = () => licenseState().full

export function serverUrl () {
  const u = String(kvGet('licenseServer', '') || DEFAULT_SERVER).trim().replace(/\/+$/, '')
  let url
  try { url = new URL(u) } catch { throw new Error('Adresse der Vedly-Zentrale ist ungültig.') }
  if (url.protocol !== 'https:' && !(['127.0.0.1', 'localhost'].includes(url.hostname) && url.protocol === 'http:')) throw new Error('Die Zentrale muss über https erreichbar sein.')
  return u
}

async function call (path, body) {
  let res
  try {
    res = await fetch(`${serverUrl()}/api/v1/${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body), signal: AbortSignal.timeout(20000) })
  } catch { throw new Error('Vedly-Zentrale nicht erreichbar. Internetverbindung prüfen.') }
  let data = {}
  try { data = await res.json() } catch { /* leer */ }
  if (!res.ok) throw new Error(data.error || `Zentrale antwortet mit ${res.status}`)
  return data
}

function store (text) {
  const lic = verifyLicense(text)
  if (!lic) throw new Error('Die Lizenz ist nicht gültig (Signatur passt nicht).')
  if (lic.installId !== installId()) throw new Error('Die Lizenz wurde für eine andere Installation erstellt.')
  kvSet('license', { text, at: new Date().toISOString() })
  kvSet('licenseReleased', null)
  const r = kvGet('licenseRevoked'); if (r && r.licenseId === lic.id) kvSet('licenseRevoked', null)
  kvSet('licenseCheck', { at: new Date().toISOString(), okAt: new Date().toISOString(), ok: true, error: null })
  return lic
}

export async function activate (key, installName) {
  const k = String(key || '').trim().toUpperCase()
  if (!/^(FLEX|MLZ|TEX|VED)(-[A-Z0-9]{4}){4}$/.test(k)) throw new Error('Lizenzschlüssel ungültig (Format VED-XXXX-XXXX-XXXX-XXXX).')
  const r = await call('activate', { key: k, installId: installId(), installName: String(installName || '').slice(0, 120), version: VERSION, product: PRODUCT })
  store(r.license)
  log('info', 'Lizenz aktiviert')
  return licenseState()
}

export async function checkin ({ force = false } = {}) {
  const stored = kvGet('license')
  const lic = stored && verifyLicense(stored.text)
  if (!lic) return licenseState()
  const last = kvGet('licenseCheck', {})
  if (!force) {
    const lastOk = last.okAt ? Date.parse(last.okAt) : Date.parse(stored.at || 0)
    if (Date.now() - lastOk < CHECK_DAYS * DAY) return licenseState()
    if (last.at && !last.ok && Date.now() - Date.parse(last.at) < 6 * 3600e3) return licenseState()
  }
  const at = new Date().toISOString()
  try {
    const r = await call('checkin', { licenseId: lic.id, installId: installId(), version: VERSION, product: PRODUCT })
    if (r.revoked) kvSet('licenseRevoked', { licenseId: lic.id, reason: r.reason || '', at })
    else if (r.released) { kvSet('license', null); kvSet('licenseReleased', { at, licenseId: lic.id }) } else if (r.license) store(r.license)
    kvSet('licenseCheck', { at, ok: true, okAt: at, error: null })
  } catch (e) {
    kvSet('licenseCheck', { ...last, at, ok: false, error: e.message })
  }
  return licenseState()
}

export async function release () {
  const stored = kvGet('license')
  const lic = stored && verifyLicense(stored.text)
  if (!lic) throw new Error('Keine Lizenz aktiviert.')
  await call('release', { licenseId: lic.id, installId: installId() })
  kvSet('license', null)
  kvSet('licenseReleased', { at: new Date().toISOString(), licenseId: lic.id })
  return licenseState()
}
