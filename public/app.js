// Kleine Helfer ohne Inline-Skripte: Rückfragen, „alle wählen“, CSV-Datei in Textfeld laden
document.addEventListener('click', (e) => {
  const b = e.target.closest('[data-confirm]')
  if (b && !window.confirm(b.getAttribute('data-confirm'))) e.preventDefault()
})
document.addEventListener('change', (e) => {
  const all = e.target.closest('[data-all]')
  if (all) document.querySelectorAll('.' + all.getAttribute('data-all')).forEach(c => { c.checked = all.checked })
  const into = e.target.closest('input[type=file][data-into]')
  if (into && into.files[0]) {
    const f = into.files[0]
    const r = new FileReader()
    r.onload = () => { document.getElementById(into.getAttribute('data-into')).value = String(r.result) }
    r.readAsText(f, /1252|latin/i.test(f.type) ? 'windows-1252' : 'utf-8')
  }
})
document.addEventListener('click', (e) => {
  if (e.target.closest('[data-print]')) { e.preventDefault(); window.print() }
})
// Auswahlliste schickt das Formular selbst ab (z. B. Postfach wechseln)
document.addEventListener('change', (e) => {
  const s = e.target.closest('[data-autosubmit]')
  if (s && s.form) s.form.submit()
})
// Mailliste alle n Sekunden neu laden – nicht, solange etwas ausgewählt oder ein Feld bearbeitet wird
;(function () {
  const el = document.querySelector('[data-refresh]')
  if (!el) return
  const sec = Math.max(30, Number(el.getAttribute('data-refresh')) || 120)
  setInterval(() => {
    if (document.hidden) return
    if (document.querySelector('input[type=checkbox]:checked') || (document.activeElement && /INPUT|SELECT|TEXTAREA/.test(document.activeElement.tagName))) return
    location.reload()
  }, sec * 1000)
})()
// Ordnerliste am Handy zuklappen
if (window.innerWidth < 800) document.querySelectorAll('details.mail-folders[open]').forEach(d => d.removeAttribute('open'))
