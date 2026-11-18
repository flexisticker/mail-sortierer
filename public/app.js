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
