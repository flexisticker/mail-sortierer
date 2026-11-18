// Gemeinsame Helfer der Weboberfläche
export const COOKIE = 'ms_sitzung'

// SameSite=Lax: Cookie kommt auch mit, wenn man über einen Link (Unraid „WebUI“, Lesezeichen) kommt.
// Schutz gegen fremde Formulare: CSRF-Feld + Herkunftsprüfung. Über HTTPS (Proxy) zusätzlich „Secure“.
export function sessionCookie (token, remember, secure) {
  return `${COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax${secure ? '; Secure' : ''}${remember ? `; Max-Age=${30 * 86400}` : ''}`
}
export const clearCookie = (secure) => `${COOKIE}=; Path=/; HttpOnly; SameSite=Lax${secure ? '; Secure' : ''}; Max-Age=0`

export function cookie (req, name) {
  const m = String(req.headers.cookie || '').split(/;\s*/).find(c => c.startsWith(name + '='))
  if (!m) return ''
  try { return decodeURIComponent(m.slice(name.length + 1)) } catch { return '' }
}

export function back (res, to, { msg, err } = {}) {
  const u = new URL(to, 'http://x')
  if (msg) u.searchParams.set('ok', String(msg).slice(0, 300))
  if (err) u.searchParams.set('fehler', String(err).slice(0, 300))
  res.redirect(303, u.pathname + u.search + u.hash)
}

export const int = (v, min, max, def) => { const n = Math.round(Number(v)); return Number.isFinite(n) ? Math.min(max, Math.max(min, n)) : def }
export const errText = (e) => String((e && (e.responseText || e.message)) || e).slice(0, 300)
export const flash = (req) => ({ msg: req.query.ok, err: req.query.fehler })
