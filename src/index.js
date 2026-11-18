// Postwart (früher Mail-Sortierer) – Start
import { kvGet, kvSet, eachUserDb } from './db.js'
import { prepareKey } from './secrets.js'
import { isExempt, checkin } from './license.js'
import { createApp } from './web.js'
import { startScheduler } from './worker.js'
import { log } from './db.js'
import { VERSION } from './html.js'
import { startUpdateCheck } from './updates.js'

const PORT = Number(process.env.PORT) || 8080

// Schlüssel für die gespeicherten Passwörter prüfen bzw. umziehen (Variable POSTWART_SCHLUESSEL) – bei falschem Schlüssel nicht starten
try { const src = prepareKey(eachUserDb); console.log(`[postwart] Schlüssel für Passwörter: ${{ env: 'Variable POSTWART_SCHLUESSEL', dpapi: 'Windows-Datenschutz', file: 'Datei im Datenordner' }[src]}`) } catch (e) {
  console.error('[postwart] ' + e.message)
  process.exit(1)
}

// Ab 1.5.0 sind die Vorgaben neutral (nichts vorausgefüllt). Bei der Eigeninstallation die bisherigen Vorgaben behalten,
// falls sie nie ausdrücklich gespeichert wurden.
if (isExempt() && !kvGet('neutralDefaultsMigrated')) {
  const c = kvGet('config', null)
  if (c) {
    c.invoices = c.invoices || {}
    if (c.invoices.ownerName === undefined) c.invoices.ownerName = 'Michael Zatti'
    if (c.invoices.companies === undefined) c.invoices.companies = 'Flexisticker\n3dbymicha'
    if (!c.ollama || c.ollama.url === undefined) c.ollama = { ...(c.ollama || {}), url: 'http://192.168.1.10:11434' }
    if (!c.business) c.business = { name: 'Flexisticker', description: 'Textil- und Tassendruck, Werbetechnik, 3D-Druck (3dbymicha)' }
    kvSet('config', c)
  }
  kvSet('neutralDefaultsMigrated', true)
}
const app = createApp()
app.listen(PORT, () => {
  log('info', `Postwart ${VERSION} gestartet (Port ${PORT})`)
  startScheduler()
  startUpdateCheck()
  // Lizenz bei der Vedly-Zentrale erneuern (prüft selbst, ob es nach 7 Tagen wieder nötig ist)
  const tick = () => { if (!isExempt()) checkin().catch(() => {}) }
  setTimeout(tick, 20000).unref()
  setInterval(tick, 6 * 3600e3).unref()
})

for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => process.exit(0))
process.on('unhandledRejection', (e) => log('error', 'Unerwarteter Fehler: ' + (e && e.message ? e.message : e)))
