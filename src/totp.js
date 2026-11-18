// Zwei-Faktor-Anmeldung mit Authenticator-App (TOTP, RFC 6238: 30 s, 6 Ziffern, SHA-1 – kompatibel mit Google/Microsoft Authenticator,
// iPhone-Passwörter, Aegis, 2FAS …). Dazu Notfallcodes (nur als SHA-256 gespeichert).
import crypto from 'node:crypto'
import qrcode from 'qrcode-generator'

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

export function newSecret () {
  const bytes = crypto.randomBytes(20)
  let bits = ''
  for (const b of bytes) bits += b.toString(2).padStart(8, '0')
  let out = ''
  for (let i = 0; i + 5 <= bits.length; i += 5) out += B32[parseInt(bits.slice(i, i + 5), 2)]
  return out
}

function b32decode (s) {
  const clean = String(s || '').toUpperCase().replace(/[^A-Z2-7]/g, '')
  let bits = ''
  for (const c of clean) bits += B32.indexOf(c).toString(2).padStart(5, '0')
  const out = []
  for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2))
  return Buffer.from(out)
}

function hotp (key, counter) {
  const buf = Buffer.alloc(8)
  buf.writeBigUInt64BE(BigInt(counter))
  const h = crypto.createHmac('sha1', key).update(buf).digest()
  const o = h[h.length - 1] & 0xf
  const n = ((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3]
  return String(n % 1e6).padStart(6, '0')
}

export const stepNow = (t = Date.now()) => Math.floor(t / 30000)

/** Code prüfen (±1 Zeitschritt). Liefert den benutzten Zeitschritt oder 0. Bereits benutzte Schritte (≤ last) zählen nicht. */
export function verifyTotp (secret, code, last = 0, t = Date.now()) {
  const c = String(code || '').replace(/\s+/g, '')
  if (!/^\d{6}$/.test(c)) return 0
  const key = b32decode(secret)
  const now = stepNow(t)
  for (const s of [now, now - 1, now + 1]) {
    if (s <= last) continue
    const want = hotp(key, s)
    if (crypto.timingSafeEqual(Buffer.from(want), Buffer.from(c))) return s
  }
  return 0
}
export const totpNow = (secret, t = Date.now()) => hotp(b32decode(secret), stepNow(t)) // nur für Tests

export function otpauthUri (secret, account, issuer = 'Postwart') {
  return `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(account)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`
}

/** QR-Code als SVG (ohne Skript, direkt in die Seite) */
export function qrSvg (text) {
  const q = qrcode(0, 'M')
  q.addData(text)
  q.make()
  const n = q.getModuleCount()
  const m = 4
  let d = ''
  for (let r = 0; r < n; r++) for (let c = 0; c < n; c++) if (q.isDark(r, c)) d += `M${c + m} ${r + m}h1v1h-1z`
  const size = n + 2 * m
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="220" height="220" class="qr" role="img" aria-label="QR-Code für die Authenticator-App"><rect width="100%" height="100%" fill="#fff"/><path d="${d}" fill="#000"/></svg>`
}

// Notfallcodes: 10 Stück „abcd-efgh-jkmn“, gespeichert nur als Hash
const ABC = 'abcdefghjkmnpqrstuvwxyz23456789'
export const sha = (s) => crypto.createHash('sha256').update(String(s)).digest('hex')
const normCode = (c) => String(c || '').toLowerCase().replace(/[^a-z0-9]/g, '')
export function newRecoveryCodes () {
  const codes = Array.from({ length: 10 }, () => Array.from({ length: 3 }, () => Array.from(crypto.randomBytes(4), b => ABC[b % ABC.length]).join('')).join('-'))
  return { codes, hashes: codes.map(c => sha(normCode(c))) }
}
/** Notfallcode prüfen → verbleibende Hashes oder null */
export function useRecoveryCode (hashes, code) {
  const h = sha(normCode(code))
  if (normCode(code).length !== 12 || !Array.isArray(hashes) || !hashes.includes(h)) return null
  return hashes.filter(x => x !== h)
}
