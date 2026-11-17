// Lokale KI über Ollama (läuft auf dem eigenen Server). Keine Anfrage geht ins Internet.

function base (cfg) {
  const u = String(cfg.ollama.url || '').trim().replace(/\/+$/, '')
  if (!/^https?:\/\//.test(u)) throw new Error('Ollama-Adresse fehlt oder ist ungültig (z. B. http://192.168.1.10:11434).')
  return u
}

async function call (cfg, path, body, timeoutSec) {
  const ctl = new AbortController()
  const t = setTimeout(() => ctl.abort(), (timeoutSec || 30) * 1000)
  try {
    const r = await fetch(base(cfg) + path, {
      method: body ? 'POST' : 'GET',
      headers: body ? { 'content-type': 'application/json' } : {},
      body: body ? JSON.stringify(body) : undefined,
      signal: ctl.signal
    })
    const text = await r.text()
    if (!r.ok) throw new Error(`Ollama antwortet mit ${r.status}: ${text.slice(0, 200)}`)
    return JSON.parse(text)
  } catch (e) {
    if (e.name === 'AbortError') throw new Error(`Ollama hat nicht innerhalb von ${timeoutSec || 30} s geantwortet.`)
    if (e.cause && e.cause.code) throw new Error(`Ollama nicht erreichbar (${e.cause.code}) unter ${base(cfg)}.`)
    throw e
  } finally { clearTimeout(t) }
}

export async function listModels (cfg) {
  const r = await call(cfg, '/api/tags', null, 10)
  return (r.models || []).map(m => ({ name: m.name, size: m.size, params: m.details && m.details.parameter_size }))
}

export async function chatJson (cfg, messages, schema) {
  const r = await call(cfg, '/api/chat', {
    model: cfg.ollama.model,
    messages,
    stream: false,
    format: schema,
    keep_alive: '15m',
    options: { temperature: 0, num_ctx: Number(cfg.ollama.numCtx) || 4096 }
  }, Number(cfg.ollama.timeoutSec) || 120)
  const content = (r.message && r.message.content) || ''
  const m = content.match(/\{[\s\S]*\}/)
  if (!m) throw new Error('KI-Antwort ohne JSON: ' + content.slice(0, 120))
  return JSON.parse(m[0])
}
