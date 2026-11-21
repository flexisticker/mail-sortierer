// Notfall-Zugang (Konsole bzw. Windows-Startmenü): Einmal-Passwort für ein Konto setzen, Zwei-Faktor zurücksetzen.
//   node src/reset-admin.js            → Konten anzeigen
//   node src/reset-admin.js <name>     → Einmal-Passwort für <name> (Konto wird als Verwalter angelegt, falls es fehlt)
// Danach: anmelden, eigenes Passwort vergeben, Authenticator-App neu einrichten.
import { sysdb as db, sysLog } from './db.js'
import { hashPassword, oneTimePassword, createUser } from './auth.js'

const name = process.argv[2]
const users = db.prepare('SELECT name, role, disabled FROM users ORDER BY id').all()
if (!name) {
  console.log('Konten:', users.length ? users.map(u => `${u.name}${u.role === 'admin' ? ' (Verwalter)' : ''}${u.disabled ? ' [gesperrt]' : ''}`).join(', ') : '(keine)')
  console.log('Einmal-Passwort setzen: node src/reset-admin.js <name>')
  process.exit(0)
}
const pw = oneTimePassword()
const u = db.prepare('SELECT * FROM users WHERE lower(name) = lower(?)').get(name)
if (u) {
  db.prepare("UPDATE users SET hash = ?, must_change = 1, disabled = 0, totp_on = 0, totp_secret = NULL, recovery = NULL, mfa_fails = 0, mfa_fail_at = 0, mfa_locked_until = 0, notice = ? WHERE id = ?")
    .run(await hashPassword(pw), 'Notfall-Zugang benutzt: bitte eigenes Passwort vergeben und die Authenticator-App neu einrichten.', u.id)
  if (u.role !== 'admin' && process.argv[3] === '--verwalter') db.prepare("UPDATE users SET role = 'admin' WHERE id = ?").run(u.id)
  db.prepare('DELETE FROM sessions WHERE user_id = ?').run(u.id)
} else {
  await createUser(name, pw, { role: 'admin', mustChange: true })
}
sysLog('warn', `Notfall-Zugang (Konsole): Einmal-Passwort für „${name}“ gesetzt, Zwei-Faktor zurückgesetzt`)
console.log(`Einmal-Passwort für ${name}: ${pw}`)
console.log('Bitte gleich anmelden: eigenes Passwort vergeben und die Authenticator-App neu einrichten.')
