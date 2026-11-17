// ============================================================================
// Verschlüsselter Fortschrittsspeicher auf GitHub (Daten-Repo)
//
// - Zugangsphrase (6 Wörter, geteilt): entschlüsselt den eingebetteten Token-Blob (config.json)
//   Die GCM-Prüfung schlägt bei falscher Phrase fehl -> kein Klartext-Canary nötig.
// - Persönliche Wörter (8 Wörter, pro Nutzer): bestimmen den Ordner im Daten-Repo (SHA-256)
//   und zusammen mit der Zugangsphrase den AES-Schlüssel (PBKDF2 -> AES-GCM).
// - Nichts wird im Browser persistiert. Schlüssel und Token leben nur im Speicher des Tabs.
// ============================================================================
(function (global) {
  'use strict';

  const ITER = 310000;
  const BRANCH = 'main';
  const te = new TextEncoder(), td = new TextDecoder();

  const S = {
    cfg: null, token: null, key: null, salt: null, sha: null, userPath: null,
    dirty: false, busy: false, again: false, timer: null,
    getState: null, setState: null, onStatus: null
  };

  // ---------- Hilfsfunktionen ----------
  function normWords(s) {
    return String(s || '').trim().toLowerCase().split(/[\s,;]+/).filter(Boolean).join(' ');
  }
  function toB64(bytes) {
    const a = new Uint8Array(bytes); let s = '';
    for (let i = 0; i < a.length; i++) s += String.fromCharCode(a[i]);
    return btoa(s);
  }
  function fromB64(str) {
    const s = atob(str); const a = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) a[i] = s.charCodeAt(i);
    return a;
  }
  function hex(buf) { return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join(''); }

  async function deriveKey(secret, salt) {
    const base = await crypto.subtle.importKey('raw', te.encode(secret), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: ITER, hash: 'SHA-256' },
      base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
    );
  }
  async function sealWith(key, salt, obj) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, te.encode(JSON.stringify(obj)));
    return { v: 1, salt: toB64(salt), iv: toB64(iv), ct: toB64(ct) };
  }
  async function openWith(key, blob) {
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromB64(blob.iv) }, key, fromB64(blob.ct));
    return JSON.parse(td.decode(pt));
  }

  // Token-Blob: Schlüssel nur aus der Zugangsphrase
  async function encryptToken(accessPhrase, token) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const key = await deriveKey(normWords(accessPhrase), salt);
    return sealWith(key, salt, { token });
  }
  async function unlockToken(blob, accessPhrase) {
    try {
      const key = await deriveKey(normWords(accessPhrase), fromB64(blob.salt));
      return (await openWith(key, blob)).token;
    } catch (e) {
      throw new Error('ZUGANG');
    }
  }

  // ---------- GitHub-API ----------
  function ghUrl(path) {
    return 'https://api.github.com/repos/' + S.cfg.dataRepo + '/contents/' + path;
  }
  function ghHeaders() {
    return { 'Accept': 'application/vnd.github+json', 'Authorization': 'Bearer ' + S.token, 'X-GitHub-Api-Version': '2022-11-28' };
  }
  async function ghGet(path) {
    const res = await fetch(ghUrl(path) + '?ref=' + BRANCH, { headers: ghHeaders(), cache: 'no-store' });
    if (res.status === 404) return null;
    if (!res.ok) throw new Error('GitHub-Lesefehler (' + res.status + ')');
    const j = await res.json();
    return { sha: j.sha, json: JSON.parse(td.decode(fromB64(j.content.replace(/\n/g, '')))) };
  }
  async function putState(state, keepalive) {
    const blob = await sealWith(S.key, S.salt, { updated: new Date().toISOString(), data: state });
    const body = {
      message: 'Fortschritt ' + new Date().toISOString().slice(0, 16),
      content: btoa(JSON.stringify(blob)),
      branch: BRANCH
    };
    if (S.sha) body.sha = S.sha;
    return fetch(ghUrl(S.userPath), {
      method: 'PUT',
      headers: Object.assign({}, ghHeaders(), { 'Content-Type': 'application/json' }),
      body: JSON.stringify(body),
      keepalive: !!keepalive
    });
  }

  // ---------- Zusammenführen bei Konflikten (zwei Geräte gleichzeitig) ----------
  // Pro Wort gewinnt der Eintrag mit dem neueren lastSeen, Freischaltung nimmt das Maximum,
  // Korrekturen werden vereinigt (lokale Änderungen gewinnen).
  function mergeStates(local, remote) {
    local = local || {}; remote = remote || {};
    const lp = local.progress || {}, rp = remote.progress || {};
    const progress = {};
    new Set([...Object.keys(lp), ...Object.keys(rp)]).forEach(id => {
      const x = lp[id], y = rp[id];
      progress[id] = !x ? y : !y ? x : (y.lastSeen > x.lastSeen ? y : x);
    });
    return {
      progress,
      manualUnlock: Math.max(local.manualUnlock || 0, remote.manualUnlock || 0),
      overrides: Object.assign({}, remote.overrides || {}, local.overrides || {})
    };
  }

  // ---------- Öffentliche Funktionen ----------
  function notify(msg, kind) { if (S.onStatus) S.onStatus(msg, kind || ''); }

  function configure(opts) {
    S.cfg = opts.cfg;
    S.getState = opts.getState;
    S.setState = opts.setState;
    S.onStatus = opts.onStatus;
  }

  // Öffnet ein Konto. Zuerst Zugangsphrase (Token), dann persönliche Wörter (Daten).
  // Wirft: NOCFG | ZUGANG | NEW | WOERTER | Fehler von GitHub/Netz
  async function unlock(personal, access, createNew) {
    if (!S.cfg || !S.cfg.tokenBlob) throw new Error('NOCFG');
    const p = normWords(personal), a = normWords(access);

    S.token = await unlockToken(S.cfg.tokenBlob, a);

    const userId = hex(await crypto.subtle.digest('SHA-256', te.encode('vt-user|' + p)));
    const path = userId + '/' + S.cfg.course + '.json';
    S.userPath = path;
    const combined = p + '|' + a;

    let remote;
    try { remote = await ghGet(path); }
    catch (e) { S.token = null; throw e; }

    if (!remote) {
      if (!createNew) { S.token = null; throw new Error('NEW'); }
      S.salt = crypto.getRandomValues(new Uint8Array(16));
      S.key = await deriveKey(combined, S.salt);
      S.sha = null;
      return { created: true, state: null };
    }

    const salt = fromB64(remote.json.salt);
    const key = await deriveKey(combined, salt);
    let payload;
    try { payload = await openWith(key, remote.json); }
    catch (e) { S.token = null; throw new Error('WOERTER'); }

    S.salt = salt; S.key = key; S.sha = remote.sha;
    return { created: false, state: payload.data || null };
  }

  function markDirty() {
    S.dirty = true;
    clearTimeout(S.timer);
    S.timer = setTimeout(() => save(), 3000);
  }

  async function save(opts) {
    opts = opts || {};
    if (!S.key || !S.userPath) return;
    if (!S.dirty && !opts.force) return;
    if (S.busy) { S.again = true; return; }
    S.busy = true; S.dirty = false; clearTimeout(S.timer);
    notify('Speichere …', '');
    try {
      let state = S.getState();
      let res = await putState(state, opts.keepalive);
      if (res.status === 409 || res.status === 422) {
        // Anderes Gerät hat zwischenzeitlich gespeichert: Stand holen, zusammenführen, erneut schreiben
        const remote = await ghGet(S.userPath);
        let rState = {};
        if (remote) {
          try { rState = (await openWith(S.key, remote.json)).data || {}; }
          catch (e) { throw new Error('Gespeicherte Daten lassen sich nicht lesen'); }
          S.sha = remote.sha;
        } else { S.sha = null; }
        state = mergeStates(state, rState);
        if (S.setState) S.setState(state);
        res = await putState(state, opts.keepalive);
      }
      if (!res.ok) throw new Error('GitHub antwortete mit ' + res.status);
      const j = await res.json();
      S.sha = j.content.sha;
      notify('✓ Gespeichert um ' + new Date().toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' }), 'ok');
    } catch (e) {
      S.dirty = true;
      notify('⚠️ Speichern fehlgeschlagen (' + e.message + '). Neuer Versuch in 30 Sekunden.', 'err');
      clearTimeout(S.timer);
      S.timer = setTimeout(() => save(), 30000);
    } finally {
      S.busy = false;
      if (S.again) { S.again = false; if (S.dirty) markDirty(); }
    }
  }

  function saveNow() { return save({ force: true }); }

  // Beim Verlassen der Seite bzw. Tab-Wechsel sichern (best effort)
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'hidden' && S.dirty) save({ keepalive: true });
  });
  window.addEventListener('pagehide', () => { if (S.dirty) save({ keepalive: true }); });

  global.VTRemote = {
    normWords, encryptToken, unlockToken, configure, unlock, markDirty, saveNow, mergeStates
  };
})(window);
