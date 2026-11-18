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
    if (document.querySelector('.mail-read[data-uid]') || document.querySelector('details.more[open]')) return
    location.reload()
  }, sec * 1000)
})()
// Ordnerliste am Handy zuklappen
if (window.innerWidth <= 1000) document.querySelectorAll('details.mail-folders[open]').forEach(d => d.removeAttribute('open'))
// Hinweise im Mail-Programm verschwinden nach ein paar Sekunden
document.querySelectorAll('.main.full > .alert.ok').forEach(a => setTimeout(() => a.remove(), 5000))

// Mail-Programm: Mail rechts öffnen, ohne die Seite neu zu laden (nur breite Bildschirme; sonst normaler Link)
;(function () {
  const pane = document.querySelector('.mail-read')
  if (!pane) return
  const wide = () => window.innerWidth > 1000
  let busy = null
  async function open (a, push) {
    if (busy) busy.abort()
    busy = new AbortController()
    pane.classList.add('loading')
    try {
      const r = await fetch(a.href, { headers: { 'X-Postwart-Teil': 'lesen' }, credentials: 'same-origin', signal: busy.signal })
      if (!r.ok || r.redirected) throw new Error('Laden fehlgeschlagen')
      const t = new DOMParser().parseFromString(await r.text(), 'text/html').querySelector('template[data-title]')
      if (!t) throw new Error('Laden fehlgeschlagen')
      pane.replaceChildren(document.importNode(t.content, true))
      pane.setAttribute('data-uid', new URL(a.href).searchParams.get('uid') || '')
      pane.scrollTop = 0
      document.title = (t.getAttribute('data-title') || 'Mail') + ' · Postwart'
      document.querySelectorAll('.mlist li.sel').forEach(li => li.classList.remove('sel'))
      const li = a.closest('li'); li.classList.add('sel'); li.classList.remove('unread')
      if (push) history.pushState({ postwart: 1 }, '', a.href)
    } catch (e) {
      if (e.name !== 'AbortError') location.href = a.href
    } finally { pane.classList.remove('loading') }
  }
  document.addEventListener('click', (e) => {
    const a = e.target.closest('.mlist a[data-read]')
    if (!a || !wide() || e.ctrlKey || e.metaKey || e.shiftKey || e.button !== 0) return
    e.preventDefault()
    open(a, true)
  })
  window.addEventListener('popstate', () => location.reload())
  // nach Verschieben/Löschen die nächste Mail öffnen
  document.addEventListener('submit', (e) => {
    const w = e.target.querySelector('input[name=weiter]')
    if (!w || w.value) return
    const li = document.querySelector('.mlist li.sel')
    const n = li && (li.nextElementSibling || li.previousElementSibling)
    const a = n && n.querySelector('a[data-read]')
    if (a) w.value = new URL(a.href).pathname + new URL(a.href).search
  }, true)
  // Pfeiltasten ↑/↓ wechseln die Mail (nicht beim Tippen)
  document.addEventListener('keydown', (e) => {
    if (!wide() || e.altKey || e.ctrlKey || e.metaKey || /INPUT|SELECT|TEXTAREA/.test((document.activeElement || {}).tagName || '')) return
    if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return
    const li = document.querySelector('.mlist li.sel')
    const n = li ? (e.key === 'ArrowDown' ? li.nextElementSibling : li.previousElementSibling) : document.querySelector('.mlist li')
    const a = n && n.querySelector('a[data-read]')
    if (!a) return
    e.preventDefault()
    open(a, true)
    a.scrollIntoView({ block: 'nearest' })
  })
})()
