// Notfall-Zugang (Konsole bzw. Windows-Startmenü): neues Passwort für ein Konto setzen.
//   node src/reset-admin.js            → Konten anzeigen
//   node src/reset-admin.js <name>     → neues Passwort für <name> (Konto wird angelegt, falls es fehlt)
import crypto from 'node:crypto'
import { db, log } from './db.js'
import { hashPassword } from './auth.js'

const name = process.argv[2]
const users = db.prepare('SELECT name FROM users ORDER BY id').all().map(u => u.name)
if (!name) {
  console.log('Konten:', users.length ? users.join(', ') : '(keine)')
  console.log('Neues Passwort setzen: node src/reset-admin.js <name>')
  process.exit(0)
}
const abc = 'abcdefghjkmnpqrstuvwxyz23456789'
const pw = Array.from({ length: 3 }, () => Array.from(crypto.randomBytes(4), b => abc[b % abc.length]).join('')).join('-')
const hash = await hashPassword(pw)
if (users.includes(name)) db.prepare('UPDATE users SET hash = ? WHERE name = ?').run(hash, name)
else db.prepare('INSERT INTO users (name, hash, created_at) VALUES (?, ?, ?)').run(name, hash, new Date().toISOString())
const u = db.prepare('SELECT id FROM users WHERE name = ?').get(name)
db.prepare('DELETE FROM sessions WHERE user_id = ?').run(u.id)
log('warn', `Notfall-Zugang: neues Passwort für „${name}“ gesetzt`)
console.log(`Neues Passwort für ${name}: ${pw}`)
console.log('Bitte gleich anmelden und unter Einstellungen → Konto ein eigenes Passwort vergeben.')
