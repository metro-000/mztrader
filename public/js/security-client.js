window.CourseSecurityClient = (() => {
  'use strict';

  const DB_NAME = 'mztrader-device-key';
  const STORE = 'keys';
  const KEY_ID = 'device-key-v1';
  const HEARTBEAT_MS = 30_000;
  const THEME_KEY = 'mztrader-theme';

  let keyPairPromise = null;
  let publicJwkPromise = null;
  let clockOffsetMs = 0;
  let streamId = null;
  let heartbeatTimer = null;

  // ── Theme Management (Dark Default + Light Toggle) ───────────────
  function initTheme() {
    const saved = localStorage.getItem(THEME_KEY) || 'dark';
    document.documentElement.setAttribute('data-theme', saved);
    updateThemeButtons(saved);
  }

  function toggleTheme() {
    const current = document.documentElement.getAttribute('data-theme') || 'dark';
    const next = current === 'dark' ? 'light' : 'dark';
    localStorage.setItem(THEME_KEY, next);
    document.documentElement.setAttribute('data-theme', next);
    updateThemeButtons(next);
  }

  function updateThemeButtons(theme) {
    document.querySelectorAll('[data-theme-toggle]').forEach((btn) => {
      btn.textContent = theme === 'dark' ? '☀️ الوضع النهاري' : '🌙 الوضع الليلي';
    });
  }

  document.addEventListener('DOMContentLoaded', () => {
    initTheme();
    document.querySelectorAll('[data-theme-toggle]').forEach((btn) => {
      btn.addEventListener('click', toggleTheme);
    });
  });

  // ── Non-extractable Device Key (IndexedDB) ───────────────────────
  const idb = (request) => new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });

  async function loadOrCreateKeyPair() {
    const openReq = indexedDB.open(DB_NAME, 1);
    openReq.onupgradeneeded = () => openReq.result.createObjectStore(STORE);
    const db = await idb(openReq);

    const existing = await idb(db.transaction(STORE).objectStore(STORE).get(KEY_ID));
    if (existing) return existing;

    // extractable=false: JS and extensions can USE the private key to sign, never EXPORT it
    const keyPair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['sign', 'verify']
    );
    await idb(db.transaction(STORE, 'readwrite').objectStore(STORE).put(keyPair, KEY_ID));
    return keyPair;
  }

  function getKeyPair() {
    if (!keyPairPromise) {
      const run = () => loadOrCreateKeyPair();
      keyPairPromise = (navigator.locks ? navigator.locks.request('mztrader-device-key', run) : run())
        .catch((err) => { keyPairPromise = null; throw err; });
    }
    return keyPairPromise;
  }

  function getPublicJwk() {
    if (!publicJwkPromise) {
      publicJwkPromise = getKeyPair()
        .then(({ publicKey }) => crypto.subtle.exportKey('jwk', publicKey))
        .then(({ kty, crv, x, y }) => ({ kty, crv, x, y }))
        .catch((err) => { publicJwkPromise = null; throw err; });
    }
    return publicJwkPromise;
  }

  // ── DPoP Proof (RFC 9449) ────────────────────────────────────────
  const b64url = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
  const b64urlJson = (obj) => b64url(new TextEncoder().encode(JSON.stringify(obj)));

  async function createDpopProof(method, url) {
    const { privateKey } = await getKeyPair();
    const header = { typ: 'dpop+jwt', alg: 'ES256', jwk: await getPublicJwk() };
    const payload = {
      jti: crypto.randomUUID(),
      htm: method,
      htu: url.origin + url.pathname,
      iat: Math.floor((Date.now() + clockOffsetMs) / 1000),
    };
    const signingInput = `${b64urlJson(header)}.${b64urlJson(payload)}`;
    const signature = await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      privateKey,
      new TextEncoder().encode(signingInput)
    );
    return `${signingInput}.${b64url(signature)}`;
  }

  // ── Fetch Wrapper with Clock-Skew Self-Healing ───────────────────
  async function apiFetch(path, { method = 'GET', json } = {}, retried = false) {
    const url = new URL(path, location.origin);
    const res = await fetch(url, {
      method,
      credentials: 'same-origin',
      headers: {
        ...(json !== undefined ? { 'Content-Type': 'application/json' } : {}),
        DPoP: await createDpopProof(method, url),
      },
      body: json !== undefined ? JSON.stringify(json) : undefined,
    });

    const serverTime = Date.parse(res.headers.get('Date'));
    if (!Number.isNaN(serverTime)) clockOffsetMs = serverTime - Date.now();
    if (res.headers.get('X-DPoP-Invalid') && !retried) {
      return apiFetch(path, { method, json }, true);
    }

    return res;
  }

  const emit = (name, detail) => document.dispatchEvent(new CustomEvent(name, { detail }));

  async function readJson(res) {
    if (res.status === 204) return {};
    try { return await res.json(); } catch { return {}; }
  }

  async function call(path, options) {
    const res = await apiFetch(path, options);
    const data = await readJson(res);
    if (res.ok) return data;
    if (data.code === 'STEP_UP_REQUIRED') emit('course:step-up-required');
    if (data.code === 'SESSION_REQUIRED') emit('course:session-expired');
    const err = new Error(data.error || `Request failed (${res.status})`);
    Object.assign(err, { status: res.status, code: data.code, data });
    throw err;
  }

  function deviceLabel() {
    const ua = navigator.userAgent;
    const os = /Android/.test(ua) ? 'Android' : /iPhone|iPad/.test(ua) ? 'iPhone/iPad'
      : /Mac/.test(ua) ? 'Mac' : /Windows/.test(ua) ? 'Windows' : /Linux/.test(ua) ? 'Linux' : 'Device';
    const browser = /Edg\//.test(ua) ? 'Edge' : /Firefox\//.test(ua) ? 'Firefox'
      : /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : 'Browser';
    return `${browser} on ${os}`;
  }

  // ── Auth & Device Methods ────────────────────────────────────────
  async function login(email, password) {
    const res = await apiFetch('/api/login', {
      method: 'POST',
      json: { email, password, deviceLabel: deviceLabel() },
    });
    const data = await readJson(res);
    if (res.status === 200) return { status: 'ok', role: data.role };
    if (res.status === 202) return { status: 'verify-device', ...data };
    const err = new Error(data.error || 'فشل تسجيل الدخول.');
    Object.assign(err, { status: res.status, code: data.code });
    throw err;
  }

  async function register({ fullName, email, phone, password, activationCode }) {
    const res = await apiFetch('/api/register', {
      method: 'POST',
      json: { fullName, email, phone, password, activationCode, deviceLabel: deviceLabel() },
    });
    const data = await readJson(res);
    if (res.ok) return { status: 'ok', ...data };
    const err = new Error(data.error || 'فشل إنشاء الحساب.');
    Object.assign(err, { status: res.status, code: data.code });
    throw err;
  }

  async function verifyDevice(pendingToken, code, replaceDeviceId = null) {
    const res = await apiFetch('/api/devices/verify', {
      method: 'POST',
      json: { pendingToken, code, replaceDeviceId },
    });
    const data = await readJson(res);
    if (res.ok) return { status: 'ok', role: data.role };
    const err = new Error(data.error || 'فشل التحقق من الكود.');
    Object.assign(err, { status: res.status, code: data.code });
    throw err;
  }

  const listDevices = () => call('/api/devices');
  const removeDevice = (id) => call(`/api/devices/${encodeURIComponent(id)}`, { method: 'DELETE' });
  const startStepUp = () => call('/api/step-up/start', { method: 'POST' });
  const verifyStepUp = (code) => call('/api/step-up/verify', { method: 'POST', json: { code } });

  async function logout() {
    stopHeartbeat();
    streamId = null;
    await call('/api/logout', { method: 'POST' }).catch(() => {});
  }

  // ── Playback & Single-Stream Heartbeat ───────────────────────────
  async function startLesson(videoId) {
    stopHeartbeat();
    const data = await call(`/api/lessons/${encodeURIComponent(videoId)}/play`, { method: 'POST' });
    streamId = data.streamId;
    return {
      manifestUrl: data.manifestUrl,
      watermark: data.watermark,
      videoTitle: data.videoTitle,
    };
  }

  async function beat() {
    if (!streamId) return;
    const res = await apiFetch('/api/stream/heartbeat', { method: 'POST', json: { streamId } });
    if (res.status === 409) {
      stopHeartbeat();
      streamId = null;
      emit('course:stream-conflict');
      return;
    }
    if (!res.ok) {
      const data = await readJson(res);
      if (data.code === 'STEP_UP_REQUIRED') emit('course:step-up-required');
      if (data.code === 'SESSION_REQUIRED') emit('course:session-expired');
    }
  }

  function onPlaying() {
    if (heartbeatTimer || !streamId) return;
    beat().catch(() => {});
    heartbeatTimer = setInterval(() => beat().catch(() => {}), HEARTBEAT_MS);
  }

  function onPaused() {
    stopHeartbeat();
  }

  function stopHeartbeat() {
    clearInterval(heartbeatTimer);
    heartbeatTimer = null;
  }

  document.addEventListener('visibilitychange', () => {
    if (!document.hidden && heartbeatTimer) beat().catch(() => {});
  });

  return {
    login,
    register,
    verifyDevice,
    logout,
    listDevices,
    removeDevice,
    startStepUp,
    verifyStepUp,
    startLesson,
    onPlaying,
    onPaused,
    call,
    apiFetch,
    toggleTheme,
  };
})();
