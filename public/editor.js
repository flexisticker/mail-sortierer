// HTML-Editor für Mails und Signaturen (ohne fremde Bibliothek). Formatierung über die Symbolleiste,
// Einfügen aus Word/Webseiten wird aufgeräumt, Bilder werden als eingebettete Bilder (data:) eingefügt.
(function () {
  const ed = document.querySelector('[data-editor]')
  if (!ed) return
  const form = ed.closest('form')
  const out = form.querySelector('input[name=html]')
  try { document.execCommand('styleWithCSS', false, false) } catch (e) { /* alte Browser */ }

  const ALLOWED = new Set(['P', 'DIV', 'SPAN', 'BR', 'B', 'STRONG', 'I', 'EM', 'U', 'S', 'STRIKE', 'SUB', 'SUP', 'FONT', 'A', 'UL', 'OL', 'LI', 'BLOCKQUOTE', 'H1', 'H2', 'H3', 'H4', 'HR', 'IMG', 'TABLE', 'THEAD', 'TBODY', 'TR', 'TD', 'TH', 'PRE', 'CODE', 'CENTER'])
  const ATTR = { A: ['href'], IMG: ['src', 'alt', 'width', 'height'], FONT: ['color', 'size', 'face'], TD: ['colspan', 'rowspan', 'align', 'valign'], TH: ['colspan', 'rowspan', 'align'], TABLE: ['border', 'cellpadding', 'cellspacing', 'width'], '*': ['align', 'style'] }
  const STYLE_OK = /^(color|background-color|font-weight|font-style|text-decoration|text-align|font-size|border-left|margin|margin-left|padding|padding-left|max-width)$/
  // Eingefügtes HTML auf erlaubte Elemente reduzieren (Word-Ballast, Skripte, Klassen fliegen raus)
  function clean (node) {
    for (const ch of [...node.childNodes]) {
      if (ch.nodeType === 8) { ch.remove(); continue }
      if (ch.nodeType !== 1) continue
      if (/^(SCRIPT|STYLE|META|LINK|TITLE|IFRAME|OBJECT|EMBED|FORM|INPUT|BUTTON|SELECT|TEXTAREA|SVG|MATH|XML)$/.test(ch.tagName) || ch.tagName.includes(':')) { ch.remove(); continue }
      clean(ch)
      if (!ALLOWED.has(ch.tagName)) { ch.replaceWith(...ch.childNodes); continue }
      const keep = (ATTR[ch.tagName] || []).concat(ATTR['*'])
      for (const a of [...ch.attributes]) {
        if (!keep.includes(a.name)) { ch.removeAttribute(a.name); continue }
        if (a.name === 'href' && !/^(https?:|mailto:|tel:)/i.test(a.value)) ch.removeAttribute('href')
        if (a.name === 'src' && !/^(data:image\/|https:)/i.test(a.value)) ch.remove()
        if (a.name === 'style') {
          const st = a.value.split(';').map(x => x.trim()).filter(x => STYLE_OK.test(x.split(':')[0].trim().toLowerCase()) && !/url\(|expression/i.test(x)).join('; ')
          if (st) ch.setAttribute('style', st); else ch.removeAttribute('style')
        }
      }
    }
    return node
  }
  // Große Bilder verkleinern (max. 1600 px), damit Mails nicht riesig werden
  function imageFile (file, cb) {
    if (!/^image\/(png|jpe?g|gif|webp)$/.test(file.type)) return
    if (file.size > 8 * 1024 * 1024) { alert('Bild ist zu groß (höchstens 8 MB).'); return }
    const r = new FileReader()
    r.onload = () => {
      if (file.type === 'image/gif') return cb(String(r.result))
      const img = new Image()
      img.onload = () => {
        const max = 1600; const k = Math.min(1, max / Math.max(img.width, img.height))
        if (k === 1 && file.size < 600 * 1024) return cb(String(r.result))
        const c = document.createElement('canvas'); c.width = Math.round(img.width * k); c.height = Math.round(img.height * k)
        c.getContext('2d').drawImage(img, 0, 0, c.width, c.height)
        cb(c.toDataURL(file.type === 'image/png' ? 'image/png' : 'image/jpeg', 0.85))
      }
      img.src = String(r.result)
    }
    r.readAsDataURL(file)
  }
  const insertImg = (src) => { ed.focus(); document.execCommand('insertHTML', false, `<img src="${src}" alt="" style="max-width: 100%">`) }

  // Symbolleiste
  document.querySelectorAll('[data-cmd]').forEach(b => {
    const run = () => {
      const cmd = b.getAttribute('data-cmd'); let val = b.getAttribute('data-val') || null
      ed.focus()
      if (cmd === 'createLink') { val = prompt('Adresse des Links (https://…):', 'https://'); if (!val || !/^(https?:\/\/|mailto:)/i.test(val)) return }
      if (b.tagName === 'SELECT' || b.type === 'color') val = b.value
      if (cmd === 'formatBlock' && val) val = '<' + val + '>'
      document.execCommand(cmd, false, val)
      if (b.tagName === 'SELECT') b.selectedIndex = 0
    }
    b.addEventListener(b.tagName === 'SELECT' || b.type === 'color' ? 'change' : 'click', (e) => { e.preventDefault(); run() })
    if (b.tagName === 'BUTTON') b.addEventListener('mousedown', (e) => e.preventDefault()) // Auswahl im Editor behalten
  })
  const imgIn = document.querySelector('[data-image-input]')
  const imgBtn = document.querySelector('[data-image]')
  if (imgBtn && imgIn) {
    imgBtn.addEventListener('click', (e) => { e.preventDefault(); imgIn.click() })
    imgIn.addEventListener('change', () => { for (const f of imgIn.files) imageFile(f, insertImg); imgIn.value = '' })
  }
  ed.addEventListener('paste', (e) => {
    const cd = e.clipboardData
    if (!cd) return
    const files = [...cd.files].filter(f => f.type.startsWith('image/'))
    if (files.length) { e.preventDefault(); files.forEach(f => imageFile(f, insertImg)); return }
    const html = cd.getData('text/html')
    if (html) {
      e.preventDefault()
      const doc = new DOMParser().parseFromString(html, 'text/html')
      document.execCommand('insertHTML', false, clean(doc.body).innerHTML)
    }
  })
  ed.addEventListener('drop', (e) => {
    const files = [...(e.dataTransfer && e.dataTransfer.files || [])].filter(f => f.type.startsWith('image/'))
    if (files.length) { e.preventDefault(); files.forEach(f => imageFile(f, insertImg)) }
  })
  ed.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); const u = prompt('Adresse des Links (https://…):', 'https://'); if (u && /^(https?:\/\/|mailto:)/i.test(u)) document.execCommand('createLink', false, u) }
  })

  // Signatur wechseln: Block mit data-signatur ersetzen
  const sigSel = form.querySelector('select[name=signatur]')
  if (sigSel) sigSel.addEventListener('change', () => {
    const tpl = document.getElementById('sig-' + sigSel.value)
    let block = ed.querySelector('[data-signatur]')
    if (!tpl) { if (block) block.remove(); return }
    if (!block) { block = document.createElement('div'); block.setAttribute('data-signatur', '1'); const q = ed.querySelector('[data-zitat]'); if (q) ed.insertBefore(block, q); else ed.appendChild(block) }
    block.innerHTML = '<br>-- <br>' + tpl.innerHTML
  })

  // Nur Text
  const plain = form.querySelector('input[name=plain]')
  const ta = form.querySelector('textarea[name=text]')
  if (plain && ta) plain.addEventListener('change', () => {
    if (plain.checked) { ta.value = ed.innerText; ed.hidden = true; ta.hidden = false; document.querySelector('.ed-tools').hidden = true }
    else { ed.hidden = false; ta.hidden = true; document.querySelector('.ed-tools').hidden = false }
  })

  // Beim Absenden: Inhalt übernehmen; versehentliches Verlassen verhindern
  let dirty = false
  ed.addEventListener('input', () => { dirty = true })
  form.addEventListener('input', () => { dirty = true })
  form.addEventListener('submit', () => { out.value = clean(ed.cloneNode(true)).innerHTML; dirty = false })
  window.addEventListener('beforeunload', (e) => { if (dirty) { e.preventDefault(); e.returnValue = '' } })
})()
