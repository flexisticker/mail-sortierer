// Mail-Sortierer – Start
import { createApp } from './web.js'
import { startScheduler } from './worker.js'
import { log } from './db.js'
import { VERSION } from './html.js'

const PORT = Number(process.env.PORT) || 8080
const app = createApp()
app.listen(PORT, () => {
  log('info', `Mail-Sortierer ${VERSION} gestartet (Port ${PORT})`)
  startScheduler()
})

for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => process.exit(0))
process.on('unhandledRejection', (e) => log('error', 'Unerwarteter Fehler: ' + (e && e.message ? e.message : e)))
