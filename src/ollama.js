// Lokale KI über Ollama (läuft im eigenen Netz). Keine Anfrage geht ins Internet.
// Mehrere Ollama-Server möglich (z. B. Unraid + PC): Anfragen werden auf alle erreichbaren verteilt,
// je Server immer nur eine gleichzeitig. Ein ausgeschalteter Server wird ein paar Minuten übersprungen.

const clean = (u) => String(u || '').trim().replace(/\/+$/, '')
const validUrl = (u) => /^https?:\/\/[^\s/]+/.test(u)

/** Alle eingetragenen Server: Haupt-Server + weitere (je mit eigenem Modell oder dem Haupt-Modell) */
export function serversOf (cfg) {
  const o = cfg.ollama || {}
  const list = [{ url: clean(o.url), model: String(o.model || '').trim(), main: true }]
  for (const x of Array.isArray(o.extra) ? o.extra : []) {
    const url = clean(x && x.url)
    if (url && validUrl(url) && !list.some(s => s.url === url)) list.push({ url, model: String((x && x.model) || '').trim() || list[0].model, main: false })
  }
  return list.filter(s => s.url)
}

// Zustand je Server (nur im Speicher): belegt, Pause nach Fehler, Statistik
const state = new Map()
const st = (url) => { if (!state.has(url)) state.set(url, { busy: false, downUntil: 0, lastError: '', lastOk: 0, count: 0, ms: 0 }); return state.get(url) }
/** Ergebnis eines Tests merken (z. B. nicht erreichbar → pausieren) */
export function noteTest (url, err) { const x = st(clean(url)); if (err) { x.lastError = err; x.downUntil = Date.now() + 3 * 60000 } else { x.lastError = ''; x.downUntil = 0 } }
export const serverStatus = (cfg) => serversOf(cfg).map(s => ({ ...s, ...st(s.url), down: st(s.url).downUntil > Date.now() }))

let waiting = 0
export const queueLength = () => waiting
const waiters = []
function wake () { while (waiters.length) waiters.shift()() }

/** Wie viele Server gerade nutzbar sind (für parallele Verarbeitung) */
export function usableServers (cfg) {
  const now = Date.now()
  return Math.max(1, serversOf(cfg).filter(s => validUrl(s.url) && st(s.url).downUntil <= now).length)
}

// Freien Server holen. Gibt es keinen erreichbaren mehr, wird es trotzdem mit dem Haupt-Server versucht (dann kommt dessen Fehler).
async function acquire (cfg, exclude) {
  const all = serversOf(cfg).filter(s => validUrl(s.url))
  if (!all.length) throw new Error('Ollama-Adresse fehlt oder ist ungültig (z. B. http://localhost:11434 oder http://<Server-IP>:11434).')
  waiting++
  try {
    for (;;) {
      const now = Date.now()
      const up = all.filter(s => !exclude.has(s.url) && st(s.url).downUntil <= now)
      const pool = up.length ? up : all.filter(s => s.main && !exclude.has(s.url))
      if (!pool.length) throw new Error(exclude.size ? 'Kein weiterer Ollama-Server erreichbar.' : 'Kein Ollama-Server erreichbar.')
      const free = pool.find(s => !st(s.url).busy)
      if (free) { st(free.url).busy = true; return free }
      await new Promise(r => { waiters.push(r); setTimeout(r, 2000) })
    }
  } finally { waiting-- }
}
function release (s) { st(s.url).busy = false; wake() }

async function request (url, path, body, timeoutSec) {
  const ctl = new AbortController()
  const t = setTimeout(() => ctl.abort(), (timeoutSec || 30) * 1000)
  try {
    const r = await fetch(url + path, {
      method: body ? 'POST' : 'GET',
      headers: body ? { 'content-type': 'application/json' } : {},
      body: body ? JSON.stringify(body) : undefined,
      signal: ctl.signal
    })
    const text = await r.text()
    if (!r.ok) { const e = new Error(`Ollama (${url}) antwortet mit ${r.status}: ${text.slice(0, 200)}`); e.status = r.status; throw e }
    return JSON.parse(text)
  } catch (e) {
    if (e.name === 'AbortError') { const x = new Error(`Ollama (${url}) hat nicht innerhalb von ${timeoutSec || 30} s geantwortet.`); x.unreachable = true; throw x }
    if (e.cause && e.cause.code) { const x = new Error(`Ollama nicht erreichbar (${e.cause.code}) unter ${url}.`); x.unreachable = true; throw x }
    throw e
  } finally { clearTimeout(t) }
}

/** Modelle eines Servers (Standard: Haupt-Server) */
export async function listModels (cfg, url) {
  const u = clean(url || (serversOf(cfg)[0] || {}).url)
  if (!validUrl(u)) throw new Error('Ollama-Adresse fehlt oder ist ungültig (z. B. http://localhost:11434 oder http://<Server-IP>:11434).')
  const r = await request(u, '/api/tags', null, 10)
  return (r.models || []).map(m => ({ name: m.name, size: m.size, params: m.details && m.details.parameter_size }))
}

async function chatOn (s, cfg, messages, schema) {
  const t0 = Date.now()
  const r = await request(s.url, '/api/chat', {
    model: s.model,
    messages,
    stream: false,
    format: schema,
    keep_alive: '15m',
    options: { temperature: 0, num_ctx: Number(cfg.ollama.numCtx) || 4096 }
  }, Number(cfg.ollama.timeoutSec) || 120)
  const x = st(s.url); x.count++; x.lastOk = Date.now(); x.lastError = ''; x.ms = Date.now() - t0
  const content = (r.message && r.message.content) || ''
  const m = content.match(/\{[\s\S]*\}/)
  if (!m) throw new Error('KI-Antwort ohne JSON: ' + content.slice(0, 120))
  return JSON.parse(m[0])
}

/**
 * Anfrage an einen freien Server. Ist ein weiterer Server nicht erreichbar (z. B. PC aus) oder fehlt dort das Modell,
 * wird er pausiert und die Anfrage auf einem anderen wiederholt.
 */
export async function chatJson (cfg, messages, schema, { server } = {}) {
  const tried = new Set()
  for (;;) {
    const s = server ? { ...serversOf(cfg).find(x => x.url === clean(server)) } : await acquire(cfg, tried)
    if (!s.url) throw new Error('Diesen Ollama-Server gibt es nicht.')
    try {
      return await chatOn(s, cfg, messages, schema)
    } catch (e) {
      const x = st(s.url); x.lastError = e.message
      const modelMissing = e.status === 404 && /model/i.test(e.message)
      if (e.unreachable || modelMissing) x.downUntil = Date.now() + (modelMissing ? 30 : 3) * 60000
      tried.add(s.url)
      const others = serversOf(cfg).some(o => !tried.has(o.url) && st(o.url).downUntil <= Date.now())
      if (server || !(e.unreachable || modelMissing) || !others) throw e
    } finally { if (!server) release(s) }
  }
}
