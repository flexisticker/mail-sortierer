// Angriffsschutz („Schutzschild“): Fallen für Bots, Erkennung von Angriffsmustern, Strafpunkte und Sperren je IP.
// Reine Logik ohne Datenbank – Speicher und Benachrichtigung reicht der Aufrufer herein.
// ACHTUNG: Kopie aus Vedly (flexisticker/flex-studio, server/shield-core.js) – Änderungen dort mitpflegen.
// Prüfskript: node scripts/shield-check.mjs (läuft in der Action).
//
// Nur Abwehr: Wer in eine Falle tappt, bekommt eine langsame, nichtssagende Antwort und wird für eine Weile gesperrt.
// Heimnetz, localhost und die Ausnahmeliste werden nie gesperrt.
import crypto from 'node:crypto';
import net from 'node:net';

// ------------------------------------------------------------ Was ist verdächtig?
// Adressen, die es bei Vedly nicht gibt, die Bots aber ständig abklappern (WordPress, PHP, Konfigurationsdateien, Router …).
// /.well-known/ bleibt frei (Zertifikate, security.txt).
export const TRAP_PATHS = [
  /^\/(wp-admin|wp-login|wp-content|wp-includes|wp-json|wp-config|wordpress|wp)(\/|\.|$)/i,
  /^\/xmlrpc\.php/i,
  /\.(php\d?|phtml|asp|aspx|ashx|asmx|jsp|jspx|cgi|pl|cfm|do|action)(\/|$|\?)/i,
  /^\/\.(?!well-known(\/|$))[^/]*/i, // /.env, /.git, /.aws, /.ssh, /.DS_Store, /.htaccess …
  /\/\.(env|git|svn|hg|aws|ssh|docker|kube|npmrc|htpasswd|htaccess)(\/|$)/i,
  /^\/(phpmyadmin|phpMyAdmin|pma|myadmin|mysqladmin|mysql|adminer|dbadmin|sqladmin|webdb)(\/|$)/i,
  /^\/(cgi-bin|server-status|server-info|actuator|jmx-console|manager\/html|host-manager|solr|jenkins|telescope|_ignition|debug\/default|console|webui)(\/|$)/i,
  /^\/(HNAP1|boaform|GponForm|goform|setup\.cgi|cgi|picsdesc\.xml|sdk|evox|nmaplowercheck|stalker_portal|owa|ecp|autodiscover|remote\/login|global-protect|\+CSCOE\+|dana-na|vpnsvc|mgmt|admin\/config)(\/|$)/i,
  /^\/(vendor\/phpunit|vendor\/|administrator|admin\.(php|html)|shell|cmd|webshell|c99|r57|backdoor|filemanager|elfinder|ckeditor|fckeditor|uploadify)(\/|$)/i,
  /\.(sql|bak|old|orig|swp|sav|tar|tgz|rar|7z|db|sqlite3?|mdb|log|ini|conf|cfg|pem|key|ppk)(\?|$)/i,
  /^\/(backup|backups|dump|database|db|old|test)\.(zip|gz|sql|tar)/i,
  /^\/(id_rsa|id_dsa|etc\/passwd|proc\/self|config\.json|credentials|secrets?)(\/|$|\.)/i,
];
// Angriffsmuster in Adresse oder Formularfeldern (Pfad-Ausbruch, SQL-Injection, Skripte, Log4Shell, Befehle)
const ATTACK = [
  /\.\.[/\\]/, /%2e%2e/i, /%252e/i, /\/etc\/(passwd|shadow|hosts)/i, /win\.ini|boot\.ini|system32/i,
  /<\s*script|javascript:|onerror\s*=|onload\s*=|<\s*svg[^>]*on\w+=/i,
  /\bunion\b[\s/*+]+(all[\s/*+]+)?select\b/i, /'\s*or\s*'?\d+'?\s*=\s*'?\d/i, /\b(sleep|benchmark|pg_sleep|waitfor\s+delay)\s*\(/i, /\binformation_schema\b/i,
  /\$\{\s*(jndi|env|sys|lower|upper|::-)/i, /%24%7b/i,
  /[;|`]\s*(wget|curl|nc|bash|sh|chmod|python|perl)\b/i, /\$\((wget|curl|bash|sh|id|whoami)/i,
  /\b(base64_decode|eval|assert|system|passthru|shell_exec)\s*\(/i, /\bphpinfo\b|allow_url_include|auto_prepend_file/i,
];
// Bekannte Angriffs- und Scan-Programme (am User-Agent erkennbar)
const SCANNERS = /sqlmap|nikto|nmap|masscan|zgrab|nuclei|wpscan|dirbuster|dirb\/|gobuster|ffuf|feroxbuster|fuzz faster|acunetix|nessus|openvas|w3af|arachni|jaeles|whatweb|wfuzz|hydra|medusa|commix|xsstrike|joomscan|droopescan|skipfish|netsparker|appscan|burp|zmeu|morfeus|jorgee|l9explore|l9tcpid|censysinspect|expanse|internet-measurement|odin\.io|leakix|httpx - open-source|python-httpx\/.*scan/i;

// Arten von Vorfällen: Punkte (ab THRESHOLD = Sperre) und Beschreibung für die Übersicht
export const KINDS = {
  trap: { points: 10, label: 'Köder-Adresse aufgerufen' },
  robots: { points: 10, label: 'Verbotene Adresse aus robots.txt aufgerufen' },
  link: { points: 10, label: 'Unsichtbarem Link gefolgt' },
  scanner: { points: 10, label: 'Scan-Programm erkannt' },
  attack: { points: 10, label: 'Angriffsmuster in der Anfrage' },
  honeypot: { points: 6, label: 'Unsichtbares Formularfeld ausgefüllt' },
  fast: { points: 4, label: 'Formular zu schnell abgeschickt' },
  miss: { points: 2, label: 'Ungültiger Link / Schlüssel probiert' },
  login: { points: 1, label: 'Fehlgeschlagene Anmeldung' },
  notfound: { points: 1, label: 'Unbekannte Adresse' },
  manual: { points: 10, label: 'Von Hand gesperrt' },
};
export const THRESHOLD = 10;
const WINDOW = 24 * 3600000;
// Sperrdauer steigt mit jeder Sperre innerhalb von 30 Tagen
const DURATIONS = [3600000, 24 * 3600000, 7 * 24 * 3600000, 30 * 24 * 3600000];
const HISTORY = 30 * 24 * 3600000;

export const DEFAULT_SHIELD = {
  enabled: true, // Fallen und Sperren aktiv
  ban: true, // aus = nur protokollieren, nichts sperren
  allowLan: true, // Heimnetz (10.x, 172.16–31.x, 192.168.x, fc00::/7) nie sperren
  allow: [], // weitere Ausnahmen: IPs oder Netze (1.2.3.4, 1.2.3.0/24, 2a01:abc::/48)
  tarpit: true, // Fallen antworten absichtlich langsam
  mail: 'daily', // off | daily | hourly – Zusammenfassung neuer Sperren per Mail
};

// ------------------------------------------------------------ IP-Adressen
/** IPv6 je /64 zählen (ein Anschluss hat Milliarden Adressen), IPv4 je Adresse. */
export function ipKey(ip) {
  const a = normIp(ip);
  if (!a.includes(':')) return a;
  const parts = a.split('%')[0].split('::');
  const head = parts[0] ? parts[0].split(':') : [];
  const tail = parts.length > 1 && parts[1] ? parts[1].split(':') : [];
  const full = parts.length > 1 ? [...head, ...Array(Math.max(0, 8 - head.length - tail.length)).fill('0'), ...tail] : head;
  return `${full.slice(0, 4).map((x) => x.toLowerCase().replace(/^0+(?=.)/, '')).join(':')}::/64`;
}
export const normIp = (ip) => String(ip || '').trim().replace(/^::ffff:(?=\d+\.\d+\.\d+\.\d+$)/i, '');

const LOCAL = new net.BlockList();
LOCAL.addSubnet('127.0.0.0', 8, 'ipv4');
LOCAL.addAddress('::1', 'ipv6');
const LAN = new net.BlockList();
for (const [a, p] of [['10.0.0.0', 8], ['172.16.0.0', 12], ['192.168.0.0', 16], ['169.254.0.0', 16]]) LAN.addSubnet(a, p, 'ipv4');
LAN.addSubnet('fc00::', 7, 'ipv6');
LAN.addSubnet('fe80::', 10, 'ipv6');

const family = (ip) => (net.isIPv4(ip) ? 'ipv4' : net.isIPv6(ip) ? 'ipv6' : null);
/** Ausnahme-Eintrag prüfen: „1.2.3.4“, „1.2.3.0/24“, „2a01:db8::/48“. Liefert null bei Unsinn. */
export function parseAllow(s) {
  const m = String(s || '').trim().match(/^([0-9a-f:.]+)(?:\/(\d{1,3}))?$/i);
  if (!m) return null;
  const fam = family(m[1]);
  if (!fam) return null;
  const max = fam === 'ipv4' ? 32 : 128;
  const prefix = m[2] == null ? max : Number(m[2]);
  if (!(prefix >= 8 && prefix <= max)) return null; // keine riesigen Netze (z. B. /0) als Ausnahme
  return { net: m[1].toLowerCase(), prefix, fam, text: prefix === max ? m[1].toLowerCase() : `${m[1].toLowerCase()}/${prefix}` };
}
function allowList(list) {
  const bl = new net.BlockList();
  for (const s of list || []) {
    const a = parseAllow(s);
    if (!a) continue;
    try { if (a.prefix === (a.fam === 'ipv4' ? 32 : 128)) bl.addAddress(a.net, a.fam); else bl.addSubnet(a.net, a.prefix, a.fam); } catch { /* ungültig */ }
  }
  return bl;
}
const inList = (bl, ip) => { const f = family(ip); return !!f && bl.check(ip, f); };

/** Pfad sicher dekodieren (doppelt kodierte Angriffe sichtbar machen). */
function decoded(s) {
  let out = String(s || '');
  for (let i = 0; i < 2; i++) { try { const d = decodeURIComponent(out); if (d === out) break; out = d; } catch { break; } }
  return out;
}

/** Was ist an dieser Anfrage verdächtig? → { kind, detail } oder null. */
export function inspect({ path = '', url = '', ua = '' }, { traps = TRAP_PATHS, extraTraps = [] } = {}) {
  const p = String(path || '');
  for (const t of extraTraps) if (t.re.test(p)) return { kind: t.kind || 'trap', detail: t.detail || p };
  if (traps.some((re) => re.test(p))) return { kind: 'trap', detail: p };
  const raw = String(url || p);
  const full = decoded(raw);
  if (ATTACK.some((re) => re.test(raw) || re.test(full))) return { kind: 'attack', detail: full.slice(0, 200) };
  if (ua && SCANNERS.test(ua)) return { kind: 'scanner', detail: String(ua).slice(0, 160) };
  return null;
}
/** Formularfelder auf Angriffsmuster prüfen (nur Text, max. 40 Felder). */
export function inspectFields(body) {
  for (const [k, v] of Object.entries(body || {}).slice(0, 40)) {
    if (typeof v !== 'string' || k === 'csrf' || k === 'ft') continue;
    if (ATTACK.some((re) => re.test(v))) return { kind: 'attack', detail: `${k}: ${v.slice(0, 160)}` };
  }
  return null;
}

// ------------------------------------------------------------ Formular-Fallen
/** Unsichtbares Feld + Zeitstempel (signiert). Das Feld „website“ füllen Menschen nie aus (nicht sichtbar, nicht per Tab erreichbar). */
export function formFields(secret, at = Date.now()) {
  const ts = String(at);
  const sig = crypto.createHmac('sha256', secret).update(`ft:${ts}`).digest('base64url').slice(0, 22);
  return `<div class="hpf" aria-hidden="true"><label>Dieses Feld bitte leer lassen <input type="text" name="website" value="" tabindex="-1" autocomplete="off"></label></div><input type="hidden" name="ft" value="${ts}.${sig}">`;
}
/**
 * Formular prüfen: { ok } oder { kind: 'honeypot'|'fast', message } (Bot) oder { stale: true } (Seite zu alt bzw. von vor dem Update).
 * minMs: so schnell füllt kein Mensch ein Formular aus.
 */
export function checkForm(body, secret, { minMs = 2000, maxMs = 14 * 24 * 3600000, now = Date.now() } = {}) {
  if (String(body?.website || '').trim()) return { kind: 'honeypot', message: 'Ihre Eingabe konnte nicht verarbeitet werden. Bitte laden Sie die Seite neu.' };
  const m = String(body?.ft || '').match(/^(\d{10,15})\.([\w-]{22})$/);
  if (!m) return { stale: true };
  const sig = crypto.createHmac('sha256', secret).update(`ft:${m[1]}`).digest('base64url').slice(0, 22);
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(m[2]))) return { stale: true };
  const age = now - Number(m[1]);
  if (age < -60000 || age > maxMs) return { stale: true };
  if (age < minMs) return { kind: 'fast', message: 'Das ging zu schnell – bitte prüfen Sie Ihre Angaben und senden Sie das Formular erneut ab.' };
  return { ok: true };
}

// ------------------------------------------------------------ Schutzschild
/**
 * store: { load() → Zustand | null, save(zustand) }   (Zustand = JSON)
 * config(): aktuelle Einstellungen (DEFAULT_SHIELD + eigene)
 * onBan(entry): neue Sperre (z. B. für die Sammelmail)
 */
export function createShield({ store, config, onBan = () => {} }) {
  const st = { bans: {}, history: {}, events: [], stats: {}, ...(safe(() => store.load()) || {}) };
  const strikes = new Map(); // ipKey → [{ at, points }]
  const trusted = new Map(); // ipKey → bis (erfolgreich angemeldet = nie sperren)
  let dirty = false, timer = null, allowCache = { src: null, bl: null };
  let holding = 0;

  function persist() {
    dirty = true;
    if (timer) return;
    timer = setTimeout(() => { timer = null; if (!dirty) return; dirty = false; try { store.save(st); } catch (e) { console.error('Schutzschild speichern:', e.message); } }, 5000);
    timer.unref?.();
  }
  const cfg = () => ({ ...DEFAULT_SHIELD, ...(safe(config) || {}) });

  /** Wird diese IP nie gesperrt? → Grund oder ''. */
  function allowedWhy(ip) {
    const a = normIp(ip);
    const c = cfg();
    if (!a || inList(LOCAL, a)) return 'localhost';
    if (c.allowLan !== false && inList(LAN, a)) return 'Heimnetz';
    const src = JSON.stringify(c.allow || []);
    if (allowCache.src !== src) allowCache = { src, bl: allowList(c.allow) };
    if (inList(allowCache.bl, a)) return 'Ausnahmeliste';
    const t = trusted.get(ipKey(a));
    if (t && t > Date.now()) return 'angemeldet';
    return '';
  }

  function banned(ip) {
    if (cfg().enabled === false || cfg().ban === false) return null;
    const k = ipKey(ip);
    const b = st.bans[k];
    if (!b) return null;
    if (b.until <= Date.now()) { delete st.bans[k]; persist(); return null; }
    if (allowedWhy(ip)) return null;
    return b;
  }

  function addEvent(e) {
    st.events.unshift(e);
    if (st.events.length > 500) st.events.length = 500;
    const day = e.at.slice(0, 10);
    const d = (st.stats[day] ||= {});
    d[e.kind] = (d[e.kind] || 0) + 1;
    const days = Object.keys(st.stats).sort();
    while (days.length > 60) delete st.stats[days.shift()];
    persist();
  }

  function ban(ip, { reason = 'manual', detail = '', where = '', ms = null, by = '' } = {}) {
    const k = ipKey(ip);
    const t = Date.now();
    const hist = (st.history[k] || []).filter((x) => x > t - HISTORY);
    const dur = ms || DURATIONS[Math.min(hist.length, DURATIONS.length - 1)];
    hist.push(t);
    st.history[k] = hist;
    const prev = st.bans[k];
    const entry = { ip: normIp(ip), key: k, at: new Date(t).toISOString(), until: Math.max(prev?.until || 0, t + dur), reason, detail: redact(detail).slice(0, 200), where, n: hist.length, hits: 0, by };
    st.bans[k] = entry;
    // Speicher begrenzen
    const keys = Object.keys(st.bans);
    if (keys.length > 5000) for (const x of keys.sort((a, b) => st.bans[a].until - st.bans[b].until).slice(0, keys.length - 5000)) delete st.bans[x];
    for (const [x, h] of Object.entries(st.history)) if (!h.some((y) => y > t - HISTORY)) delete st.history[x];
    persist();
    safe(() => onBan(entry));
    return entry;
  }

  /** Strafpunkte vergeben. Liefert { banned, entry, allowed }. */
  function strike(ip, kind, { detail = '', where = '', path = '', ua = '', points = null } = {}) {
    const c = cfg();
    if (c.enabled === false) return { banned: false };
    const pts = points ?? KINDS[kind]?.points ?? 1;
    const t = Date.now();
    const why = allowedWhy(ip);
    const ev = { at: new Date(t).toISOString(), ip: normIp(ip).slice(0, 64), kind, points: why ? 0 : pts, where, path: redact(path).slice(0, 200), detail: redact(detail).slice(0, 200), ua: String(ua).slice(0, 160), allowed: why || undefined };
    if (why) { addEvent(ev); return { banned: false, allowed: why }; }
    const k = ipKey(ip);
    const list = (strikes.get(k) || []).filter((s) => s.at > t - WINDOW);
    list.push({ at: t, points: pts });
    strikes.set(k, list);
    if (strikes.size > 20000) for (const [x, l] of strikes) { if (!l.some((s) => s.at > t - WINDOW)) strikes.delete(x); if (strikes.size < 18000) break; }
    const score = list.reduce((s, x) => s + x.points, 0);
    if (score >= THRESHOLD && c.ban !== false && !banned(ip)) {
      strikes.delete(k);
      const entry = ban(ip, { reason: kind, detail: detail || path, where });
      ev.banned = true;
      ev.until = new Date(entry.until).toISOString();
      addEvent(ev);
      return { banned: true, entry };
    }
    addEvent(ev);
    return { banned: false, score };
  }

  /**
   * Express-Middleware: gesperrte IPs abweisen, Fallen und Angriffsmuster erkennen.
   * where = 'portal' | 'app' | 'zentrale'; blocked(req, res, entry) schreibt die Sperrseite.
   */
  function middleware(where, { blocked, trap, extraTraps = [], skip = null } = {}) {
    return (req, res, next) => {
      const c = cfg();
      if (c.enabled === false) return next();
      const b = banned(req.ip);
      if (b) {
        b.hits = (b.hits || 0) + 1;
        b.lastHit = new Date().toISOString();
        if (b.hits % 25 === 1) persist();
        return blocked ? blocked(req, res, b) : res.status(403).type('text/plain; charset=utf-8').send('Zugriff gesperrt.');
      }
      if (skip && skip(req)) return next();
      const hit = inspect({ path: req.path, url: req.originalUrl, ua: req.get('user-agent') || '' }, { extraTraps });
      if (!hit) return next();
      const r = strike(req.ip, hit.kind, { detail: hit.detail, where, path: req.originalUrl, ua: req.get('user-agent') || '' });
      // Erkannt, aber Heimnetz/Ausnahme: ganz normal 404 ohne Verzögerung
      if (r.allowed) return trap ? trap(req, res, hit) : res.status(404).type('text/plain; charset=utf-8').send('Nicht gefunden.');
      return tarpit(res, () => (trap ? trap(req, res, hit) : res.status(404).type('text/plain; charset=utf-8').send('Nicht gefunden.')));
    };
  }

  /** Langsam antworten (Bot verliert Zeit), höchstens 40 gleichzeitig – sonst sofort. */
  function tarpit(res, fn) {
    if (cfg().tarpit === false || holding >= 40) return fn();
    holding++;
    const ms = 4000 + Math.floor(Math.random() * 6000);
    let done = false;
    const finish = () => { if (done) return; done = true; holding--; clearTimeout(tm); if (!res.writableEnded && !res.destroyed) fn(); };
    const tm = setTimeout(finish, ms);
    res.on('close', () => { if (!done) { done = true; holding--; clearTimeout(tm); } });
  }

  return {
    config: cfg,
    allowedWhy,
    banned,
    ban,
    strike,
    middleware,
    tarpit,
    /** Erfolgreich angemeldet: diese IP 30 Tage nie automatisch sperren. */
    trust(ip, days = 30) { const k = ipKey(ip); trusted.set(k, Date.now() + days * 86400000); if (st.bans[k]) { delete st.bans[k]; persist(); } },
    unban(key) { const k = String(key || ''); const hit = st.bans[k] || st.bans[ipKey(k)]; if (!hit) return false; delete st.bans[hit.key]; delete st.history[hit.key]; strikes.delete(hit.key); persist(); return true; },
    clearEvents() { st.events = []; st.stats = {}; persist(); },
    /** Übersicht für die Einstellungen. */
    overview({ events = 200 } = {}) {
      const t = Date.now();
      const bans = Object.values(st.bans).filter((b) => b.until > t).sort((a, b) => b.at.localeCompare(a.at));
      const days = Object.keys(st.stats).sort().reverse();
      const sum = (n) => days.slice(0, n).reduce((s, d) => s + Object.values(st.stats[d]).reduce((a, b) => a + b, 0), 0);
      const kinds = {};
      for (const d of days.slice(0, 30)) for (const [k, v] of Object.entries(st.stats[d])) kinds[k] = (kinds[k] || 0) + v;
      return { bans, events: st.events.slice(0, events), stats: { today: sum(1), week: sum(7), month: sum(30), kinds, bansTotal: bans.length }, kinds: KINDS };
    },
    flush() { if (dirty) { dirty = false; safe(() => store.save(st)); } },
    _state: st,
  };
}

function safe(fn) { try { return fn(); } catch { return null; } }
// Zugangslinks des Kundenportals (/f/<Token>) nie vollständig ins Protokoll schreiben
const redact = (p) => String(p || '').replace(/\/f\/([A-Za-z0-9_-]{6})[A-Za-z0-9_-]{16,}/g, '/f/$1…');
