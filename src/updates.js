// Update-Prüfung: liest die Version des Images :latest auf ghcr.io (öffentliches Paket, ohne Anmeldung).
// Es geht nur eine Anfrage an ghcr.io – keine Daten über Nutzer oder Mails.
import { sysGet, sysSet } from './db.js'
import { VERSION } from './html.js'

const IMAGE = 'flexisticker/mail-sortierer'
export const newer = (a, b) => { const x = String(a).split('.').map(Number); const y = String(b).split('.').map(Number); for (let i = 0; i < 3; i++) { if ((x[i] || 0) !== (y[i] || 0)) return (x[i] || 0) > (y[i] || 0) } return false }

export async function checkUpdate () {
  const t = await (await fetch(`https://ghcr.io/token?scope=repository:${IMAGE}:pull`)).json()
  const h = { Authorization: `Bearer ${t.token}`, Accept: 'application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.docker.distribution.manifest.list.v2+json' }
  let m = await (await fetch(`https://ghcr.io/v2/${IMAGE}/manifests/latest`, { headers: h })).json()
  if (m.manifests) {
    const pick = m.manifests.find(x => x.platform && x.platform.architecture === 'amd64') || m.manifests[0]
    m = await (await fetch(`https://ghcr.io/v2/${IMAGE}/manifests/${pick.digest}`, { headers: h })).json()
  }
  const cfg = await (await fetch(`https://ghcr.io/v2/${IMAGE}/blobs/${m.config.digest}`, { headers: { Authorization: h.Authorization } })).json()
  const latest = ((cfg.config || {}).Labels || {})['de.flexisticker.version'] || ''
  const r = { at: new Date().toISOString(), latest, current: VERSION, update: !!latest && newer(latest, VERSION) }
  sysSet('updateCheck', r)
  return r
}
export const updateState = () => sysGet('updateCheck', null)
export function startUpdateCheck () {
  const tick = () => { const s = updateState(); if (!s || Date.now() - Date.parse(s.at) > 20 * 3600e3) checkUpdate().catch(e => sysSet('updateCheck', { ...(updateState() || {}), at: new Date().toISOString(), error: e.message })) }
  setTimeout(tick, 60000).unref()
  setInterval(tick, 3 * 3600e3).unref()
}
