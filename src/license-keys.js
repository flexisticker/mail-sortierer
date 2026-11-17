// Öffentlicher Schlüssel der Vedly-Zentrale – damit gelten nur dort unterschriebene Lizenzen (gleich wie in Vedly server/license-keys.js).
// Der geheime Gegenschlüssel liegt ausschließlich in der Zentrale.
export const TRUSTED_KEYS = [
  // Zentrale auf Unraid (PowerServer), erzeugt 29.10.2026
  `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA3u3S0i5Ntv4hPM5hA9kPAdILQMw/NPvWiLIfmvrlzXc=
-----END PUBLIC KEY-----`
]
