'use strict';
/**
 * MZTRADER - Protected Video Course Platform
 * Node 20+ & Express 5 | RFC 9449 DPoP | 2-Device Cap | 1-Stream Lease | AES-128 HLS + Moving Watermark
 */
const crypto = require('node:crypto');
const dns = require('node:dns');
const http = require('node:http');
const https = require('node:https');
const net = require('node:net');
const path = require('node:path');
dns.setDefaultResultOrder('ipv4first');
net.setDefaultAutoSelectFamilyAttemptTimeout?.(500);
const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const { rateLimit } = require('express-rate-limit');
const argon2 = require('argon2');
const jwt = require('jsonwebtoken');
const db = require('./db');
const risk = require('./risk');
const mailer = require('./mailer');

// ── 1. Configuration ───────────────────────────────────────────────
const JWT_SECRET = process.env.JWT_SECRET || 'mztrader-production-grade-jwt-secret-key-2026-min32chars';
const PORT = Number(process.env.PORT ?? 3000);
const IS_PROD = process.env.NODE_ENV === 'production';
const PUBLIC_ORIGIN = process.env.PUBLIC_ORIGIN ? new URL(process.env.PUBLIC_ORIGIN).origin : null;

const POLICY = Object.freeze({
  MAX_DEVICES: 2,
  MAX_DEVICE_CHANGES_PER_30D: 2,
  SESSION_TTL_S: 7 * 86400,
  PENDING_TTL_S: 10 * 60,
  DPOP_MAX_SKEW_S: 300,
  TAKEOVER_WINDOW_S: 60,
  HLS_TOKEN_TTL_S: 2 * 3600,
});

const SESSION_COOKIE = IS_PROD ? '__Host-session' : 'mz_session';
const COOKIE_OPTS = {
  httpOnly: true,
  secure: IS_PROD,
  sameSite: 'strict',
  path: '/',
};

const SAFE_VIDEO_ID = /^[a-zA-Z0-9_-]{1,64}$/;

// Timing-safe dummy hash so unknown emails take the same time as wrong passwords
const dummyHashPromise = argon2.hash(crypto.randomUUID());

// ── 2. App Hardening & Strict CSP ──────────────────────────────────
const app = express();
app.set('trust proxy', Number(process.env.TRUST_PROXY_HOPS ?? 1));

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com', 'data:'],
      mediaSrc: ["'self'", 'blob:', 'https:'],
      workerSrc: ["'self'", 'blob:'],
      connectSrc: ["'self'", 'https:'],
      imgSrc: ["'self'", 'data:', 'https:'],
      frameSrc: ["'none'"],
      objectSrc: ["'none'"],
      baseUri: ["'none'"],
      frameAncestors: ["'none'"],
    },
  },
  strictTransportSecurity: IS_PROD
    ? { maxAge: 63072000, includeSubDomains: true, preload: true }
    : false,
}));

app.use(express.json({ limit: '25kb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// ── 3. Rate Limits (per IP AND per email) ──────────────────────────
const limiterBase = {
  windowMs: 15 * 60 * 1000,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'محاولات كثيرة جداً. يرجى الانتظار 15 دقيقة.' },
};
const ipLimiter = rateLimit({ ...limiterBase, limit: 120 });
const emailLimiter = rateLimit({
  ...limiterBase,
  limit: 20,
  keyGenerator: (req) => `email:${String(req.body?.email ?? '').trim().toLowerCase()}`,
});

// ── 4. DPoP (RFC 9449) Verification ────────────────────────────────
const decodeJson = (part) => JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
const sha256b64url = (str) => crypto.createHash('sha256').update(str).digest('base64url');

function getExpectedOrigin(req) {
  if (PUBLIC_ORIGIN) return PUBLIC_ORIGIN;
  const xfProto = String(req.get('x-forwarded-proto') || '').split(',')[0].trim();
  const proto = IS_PROD || req.secure || xfProto === 'https' ? 'https' : (req.protocol || 'http');
  const host = req.get('x-forwarded-host') || req.get('host') || `127.0.0.1:${PORT}`;
  return `${proto}://${host}`;
}

async function verifyDpop(req) {
  const proof = req.get('DPoP');
  if (typeof proof !== 'string' || proof.length > 2048) return null;

  const parts = proof.split('.');
  if (parts.length !== 3) return null;
  const [h, p, s] = parts;

  let header, payload;
  try {
    header = decodeJson(h);
    payload = decodeJson(p);
  } catch {
    return null;
  }
  if (!header || !payload) return null;

  const jwk = header.jwk;
  if (
    header.typ !== 'dpop+jwt' ||
    header.alg !== 'ES256' ||
    !jwk ||
    jwk.kty !== 'EC' ||
    jwk.crv !== 'P-256' ||
    typeof jwk.x !== 'string' ||
    typeof jwk.y !== 'string' ||
    'd' in jwk
  ) {
    return null;
  }

  const expectedHtu = getExpectedOrigin(req) + req.originalUrl.split('?')[0];
  if (payload.htm !== req.method || payload.htu !== expectedHtu) return null;
  if (typeof payload.jti !== 'string' || payload.jti.length < 16 || payload.jti.length > 64) return null;

  const now = Math.floor(Date.now() / 1000);
  if (!Number.isInteger(payload.iat) || Math.abs(now - payload.iat) > POLICY.DPOP_MAX_SKEW_S) return null;

  // RFC 7638 canonical JWK member order: crv, kty, x, y
  const canonicalJwk = JSON.stringify({ crv: 'P-256', kty: 'EC', x: jwk.x, y: jwk.y });
  try {
    const key = crypto.createPublicKey({ key: JSON.parse(canonicalJwk), format: 'jwk' });
    const valid = crypto.verify(
      'sha256',
      Buffer.from(`${h}.${p}`),
      { key, dsaEncoding: 'ieee-p1363' },
      Buffer.from(s, 'base64url')
    );
    if (!valid) return null;
  } catch {
    return null;
  }

  if (!(await db.consumeDpopJti(payload.jti, payload.iat + 2 * POLICY.DPOP_MAX_SKEW_S))) {
    return null;
  }

  return { jkt: sha256b64url(canonicalJwk), publicKeyJwk: canonicalJwk };
}

function rejectProof(res) {
  res.set('X-DPoP-Invalid', '1');
  return res.status(401).json({ error: 'تعذر التحقق من البصمة المشفرة للجهاز.', code: 'DPOP_INVALID' });
}

// ── 5. Session Management ──────────────────────────────────────────
function issueSession(res, user, jkt) {
  const token = jwt.sign(
    { typ: 'session', uid: user.id, jkt, ver: user.session_version },
    JWT_SECRET,
    { algorithm: 'HS256', expiresIn: POLICY.SESSION_TTL_S }
  );
  res.cookie(SESSION_COOKIE, token, { ...COOKIE_OPTS, maxAge: POLICY.SESSION_TTL_S * 1000 });
}

function verifyJwt(token, typ) {
  try {
    const claims = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
    return claims.typ === typ ? claims : null;
  } catch {
    return null;
  }
}

function requireSession({ allowStepUp = false, requireAdmin = false } = {}) {
  return async (req, res, next) => {
    const dpop = await verifyDpop(req);
    if (!dpop) return rejectProof(res);

    const claims = verifyJwt(req.cookies?.[SESSION_COOKIE] ?? '', 'session');
    if (!claims) {
      return res.status(401).json({ error: 'يرجى تسجيل الدخول للمتابعة.', code: 'SESSION_REQUIRED' });
    }

    if (claims.jkt !== dpop.jkt) {
      await risk.record(claims.uid, 'key_mismatch', req.ip, {
        note: 'محاولة استخدام جلسة على جهاز مختلف عن الجهاز المربوط بالمفتاح المشفر',
      });
      return res.status(401).json({ error: 'هذه الجلسة مربوطة بجهاز آخر ولا يمكن نقلها.', code: 'SESSION_REQUIRED' });
    }

    const user = await db.findUserById(claims.uid);
    if (!user || user.session_version !== claims.ver) {
      return res.status(401).json({ error: 'انتهت الجلسة. يرجى تسجيل الدخول مجدداً.', code: 'SESSION_REQUIRED' });
    }
    if (user.is_banned) {
      return res.status(403).json({
        error: `تم إيقاف الحساب: ${user.ban_reason || 'تواصل مع الإدارة.'}`,
        code: 'BANNED',
      });
    }

    const device = await db.findDevice(user.id, dpop.jkt);
    if (!device) {
      return res.status(401).json({ error: 'تمت إزالة هذا الجهاز من حسابك. يرجى تسجيل الدخول مجدداً.', code: 'SESSION_REQUIRED' });
    }

    const newlyFlagged = await risk.checkLocation(user, req);
    await db.touchDevice(device.id, req.ip);

    if ((user.requires_step_up || newlyFlagged) && !allowStepUp && user.role !== 'admin') {
      return res.status(403).json({ error: 'يرجى تأكيد هويتك بكود التحقق للمتابعة.', code: 'STEP_UP_REQUIRED' });
    }

    if (requireAdmin && user.role !== 'admin') {
      return res.status(403).json({ error: 'غير مصرح لك بالوصول إلى لوحة الإدارة.', code: 'FORBIDDEN' });
    }

    req.user = user;
    req.device = device;
    req.dpop = dpop;
    next();
  };
}

// ── 6. Auth, Registration & Device Routes ──────────────────────────
app.post('/api/register', ipLimiter, emailLimiter, async (req, res) => {
  const { fullName, email, phone, password, activationCode, deviceLabel } = req.body ?? {};
  if (!fullName || !email || !password || String(password).length < 6) {
    return res.status(400).json({ error: 'يرجى إدخال الاسم، البريد الإلكتروني، وكلمة مرور من 6 أحرف على الأقل.' });
  }
  const dpop = await verifyDpop(req);
  if (!dpop) return rejectProof(res);

  const passwordHash = await argon2.hash(String(password));
  let user;
  try {
    user = await db.createUser({
      fullName,
      email,
      phone,
      passwordHash,
      activationCode,
    });
  } catch (err) {
    if (err.code === 'EMAIL_EXISTS' || err.code === 'INVALID_ACTIVATION_CODE') {
      return res.status(400).json({ error: err.message, code: err.code });
    }
    throw err;
  }

  // Register the creator's first device immediately on sign-up
  const label = String(deviceLabel ?? 'متصفح الويب').slice(0, 100);
  await db.registerDeviceAtomic({
    userId: user.id,
    jkt: dpop.jkt,
    publicKeyJwk: dpop.publicKeyJwk,
    label,
    ip: req.ip,
    replaceDeviceId: null,
    maxDevices: POLICY.MAX_DEVICES,
    maxChangesPer30d: POLICY.MAX_DEVICE_CHANGES_PER_30D,
  });
  await risk.record(user.id, 'device_registered', req.ip, { label, via: 'register' });

  issueSession(res, user, dpop.jkt);
  return res.status(201).json({ ok: true, role: user.role, watermarkCode: user.watermark_code });
});

app.post('/api/login', ipLimiter, emailLimiter, async (req, res) => {
  db.pruneExpired().catch(() => {});
  const { email, password, deviceLabel } = req.body ?? {};
  if (typeof email !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'البريد الإلكتروني وكلمة المرور مطلوبان.' });
  }
  const dpop = await verifyDpop(req);
  if (!dpop) return rejectProof(res);

  const user = await db.findUserByEmail(email.trim().toLowerCase());
  const hash = user?.password_hash ?? (await dummyHashPromise);
  const passwordOk = await argon2.verify(hash, password).catch(() => false);
  if (!user || !passwordOk) {
    return res.status(401).json({ error: 'البريد الإلكتروني أو كلمة المرور غير صحيحة.' });
  }
  if (user.is_banned) {
    return res.status(403).json({
      error: `تم حظر هذا الحساب: ${user.ban_reason || 'يرجى التواصل مع الدعم.'}`,
      code: 'BANNED',
    });
  }

  // Known registered device -> issue session immediately
  if (await db.findDevice(user.id, dpop.jkt)) {
    issueSession(res, user, dpop.jkt);
    return res.json({ ok: true, role: user.role });
  }

  const label = String(deviceLabel ?? 'متصفح الويب').slice(0, 100);
  const devices = await db.listDevices(user.id);

  // First-ever device on a freshly seeded demo/admin account -> auto-bind first slot for smooth onboarding,
  // OR if user already has >=1 device (or wants OTP), require 6-digit verification code.
  if (devices.length === 0) {
    await db.registerDeviceAtomic({
      userId: user.id,
      jkt: dpop.jkt,
      publicKeyJwk: dpop.publicKeyJwk,
      label,
      ip: req.ip,
      replaceDeviceId: null,
      maxDevices: POLICY.MAX_DEVICES,
      maxChangesPer30d: POLICY.MAX_DEVICE_CHANGES_PER_30D,
    });
    await risk.record(user.id, 'device_registered', req.ip, { label, firstDevice: true });
    issueSession(res, user, dpop.jkt);
    return res.json({ ok: true, role: user.role });
  }

  // New unrecognized device -> require 6-digit email verification code
  const code = await db.createEmailCode(user.id, 'new_device', dpop.jkt);
  await mailer.sendDeviceCode(user.email, code, { deviceLabel: label, ip: req.ip });

  const changesUsed = await db.countRecentDeviceChanges(user.id);
  const pendingToken = jwt.sign(
    { typ: 'device_verify', uid: user.id, jkt: dpop.jkt, label },
    JWT_SECRET,
    { algorithm: 'HS256', expiresIn: POLICY.PENDING_TTL_S }
  );

  return res.status(202).json({
    code: 'DEVICE_VERIFICATION_REQUIRED',
    pendingToken,
    atLimit: devices.length >= POLICY.MAX_DEVICES,
    devices: devices.map((d) => ({ id: d.id, label: d.device_label, lastSeenAt: d.last_seen_at })),
    changesLeft: Math.max(0, POLICY.MAX_DEVICE_CHANGES_PER_30D - changesUsed),
    devCodeHint: !process.env.RESEND_API_KEY ? code : undefined,
  });
});

app.post('/api/devices/verify', ipLimiter, async (req, res) => {
  const { pendingToken, code, replaceDeviceId } = req.body ?? {};
  const dpop = await verifyDpop(req);
  if (!dpop) return rejectProof(res);

  const pending = verifyJwt(String(pendingToken ?? ''), 'device_verify');
  if (!pending || pending.jkt !== dpop.jkt) {
    return res.status(401).json({ error: 'انتهت صلاحية جلسة التحقق. يرجى تسجيل الدخول من جديد.' });
  }
  const user = await db.findUserById(pending.uid);
  if (!user || user.is_banned) {
    return res.status(403).json({ error: 'الحساب غير متاح حالياً.' });
  }

  if (!(await db.verifyEmailCode(user.id, 'new_device', dpop.jkt, String(code ?? '')))) {
    return res.status(401).json({ error: 'كود التحقق غير صحيح أو منتهي الصلاحية.', code: 'CODE_INVALID' });
  }

  const result = await db.registerDeviceAtomic({
    userId: user.id,
    jkt: dpop.jkt,
    publicKeyJwk: dpop.publicKeyJwk,
    label: pending.label,
    ip: req.ip,
    replaceDeviceId: replaceDeviceId ? Number(replaceDeviceId) : null,
    maxDevices: POLICY.MAX_DEVICES,
    maxChangesPer30d: POLICY.MAX_DEVICE_CHANGES_PER_30D,
  });

  if (result.status === 'limit') {
    return res.status(409).json({
      error: 'وصلت للحد الأقصى للأجهزة (جهازين). يرجى اختيار جهاز لاستبداله.',
      code: 'DEVICE_LIMIT_REACHED',
    });
  }
  if (result.status === 'quota') {
    return res.status(429).json({
      error: 'لقد استنفدت الحد الأقصى لاستبدال الأجهزة هذا الشهر (مرتين كل 30 يوماً). تواصل مع الإدارة.',
      code: 'DEVICE_CHANGE_QUOTA',
    });
  }

  await risk.record(user.id, result.replaced ? 'device_replaced' : 'device_registered', req.ip, { label: pending.label });
  await mailer.sendNewDeviceAlert(user.email, { deviceLabel: pending.label, ip: req.ip, replaced: result.replaced });

  issueSession(res, user, dpop.jkt);
  return res.json({ ok: true, role: user.role });
});

app.get('/api/devices', requireSession({ allowStepUp: true }), async (req, res) => {
  const devices = await db.listDevices(req.user.id);
  const changesUsed = await db.countRecentDeviceChanges(req.user.id);
  res.json({
    devices: devices.map((d) => ({
      id: d.id,
      label: d.device_label,
      ip: d.last_ip,
      lastSeenAt: d.last_seen_at,
      current: d.id === req.device.id,
    })),
    maxDevices: POLICY.MAX_DEVICES,
    changesLeft: Math.max(0, POLICY.MAX_DEVICE_CHANGES_PER_30D - changesUsed),
  });
});

app.delete('/api/devices/:id', requireSession({ allowStepUp: true }), async (req, res) => {
  const deviceId = Number(req.params.id);
  const result = await db.removeDeviceWithQuota(req.user.id, deviceId, POLICY.MAX_DEVICE_CHANGES_PER_30D);
  if (result === 'not_found') return res.status(404).json({ error: 'الجهاز غير موجود.' });
  if (result === 'quota') {
    return res.status(429).json({
      error: 'لقد استنفدت الحد الأقصى لحذف أو استبدال الأجهزة هذا الشهر (مرتين كل 30 يوماً).',
      code: 'DEVICE_CHANGE_QUOTA',
    });
  }

  await risk.record(req.user.id, 'device_removed', req.ip);
  if (deviceId === req.device.id) res.clearCookie(SESSION_COOKIE, COOKIE_OPTS);
  res.status(204).end();
});

app.post('/api/logout', requireSession({ allowStepUp: true }), async (req, res) => {
  await db.releaseStream(req.user.id, req.device.id);
  res.clearCookie(SESSION_COOKIE, COOKIE_OPTS);
  res.status(204).end();
});

// ── 7. Step-Up Verification (Replaces Auto-Bans) ───────────────────
app.post('/api/step-up/start', ipLimiter, requireSession({ allowStepUp: true }), async (req, res) => {
  const code = await db.createEmailCode(req.user.id, 'step_up', req.device.jwk_thumbprint);
  await mailer.sendStepUpCode(req.user.email, code);
  res.status(202).json({
    ok: true,
    devCodeHint: !process.env.RESEND_API_KEY ? code : undefined,
  });
});

app.post('/api/step-up/verify', ipLimiter, requireSession({ allowStepUp: true }), async (req, res) => {
  const ok = await db.verifyEmailCode(req.user.id, 'step_up', req.device.jwk_thumbprint, String(req.body?.code ?? ''));
  if (!ok) return res.status(401).json({ error: 'كود التحقق غير صحيح أو منتهي الصلاحية.', code: 'CODE_INVALID' });
  await risk.clearAfterStepUp(req.user.id, req.ip);
  res.json({ ok: true });
});

// ── 8. Student Portal & Activation Routes ──────────────────────────
app.get('/api/portal/overview', requireSession({ allowStepUp: true }), async (req, res) => {
  const isEnrolled = await db.isUserEnrolled(req.user.id);
  const course = isEnrolled ? await db.getCourseCurriculumForUser(req.user.id) : null;
  const devices = await db.listDevices(req.user.id);
  const changesUsed = await db.countRecentDeviceChanges(req.user.id);

  res.json({
    user: {
      id: req.user.id,
      fullName: req.user.full_name,
      email: req.user.email,
      phone: req.user.phone,
      role: req.user.role,
      watermarkCode: req.user.watermark_code,
      requiresStepUp: req.user.requires_step_up,
      isEnrolled,
    },
    currentDevice: {
      id: req.device.id,
      label: req.device.device_label,
    },
    devices: devices.map((d) => ({
      id: d.id,
      label: d.device_label,
      ip: d.last_ip,
      lastSeenAt: d.last_seen_at,
      current: d.id === req.device.id,
    })),
    changesLeft: Math.max(0, POLICY.MAX_DEVICE_CHANGES_PER_30D - changesUsed),
    course,
  });
});

app.post('/api/enroll/activate', requireSession(), async (req, res) => {
  const { code } = req.body ?? {};
  const result = await db.redeemActivationCode(req.user.id, code);
  if (!result.ok) {
    return res.status(400).json({ error: result.error });
  }
  res.json({ ok: true });
});

app.post('/api/lessons/:videoId/complete', requireSession(), async (req, res) => {
  const { videoId } = req.params;
  if (!(await db.hasEntitlement(req.user.id, videoId))) {
    return res.status(403).json({ error: 'غير مشترك في هذا الكورس.' });
  }
  await db.toggleLessonComplete(req.user.id, videoId, Boolean(req.body?.completed ?? true));
  const course = await db.getCourseCurriculumForUser(req.user.id);
  res.json({ ok: true, completedCount: course?.completedCount ?? 0, totalLessons: course?.totalLessons ?? 0 });
});

app.get('/api/lessons/:videoId/attachment', requireSession(), async (req, res) => {
  const { videoId } = req.params;
  if (!(await db.hasEntitlement(req.user.id, videoId))) {
    return res.status(403).send('غير مصرح');
  }
  const video = await db.getVideoById(videoId);
  if (!video) return res.status(404).send('غير موجود');

  const filename = encodeURIComponent(video.attachment_name || `${video.id}-MZTRADER.html`);
  res.set({
    'Content-Type': 'text/html; charset=utf-8',
    'Content-Disposition': `attachment; filename="${filename}.html"`,
  });
  res.send(`<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head><meta charset="utf-8"><title>${video.title} - MZTRADER</title>
<style>body{font-family:sans-serif;padding:40px;background:#0B0E14;color:#F8FAFC;line-height:1.8}
.box{border:1px solid #1E293B;background:#151A24;padding:24px;border-radius:12px;max-width:800px;margin:auto}
.wm{color:#E50914;font-family:monospace;font-weight:bold}</style></head>
<body><div class="box">
<h1>MZTRADER</h1>
<h2>${video.title}</h2>
<p>${video.description}</p>
<hr style="border-color:#1E293B">
<p>نسخة مرخصة للمشترك: <strong>${req.user.full_name}</strong> (<span class="wm">ID: ${req.user.watermark_code}</span>)</p>
</div></body></html>`);
});

// ── 9. Protected Video Pipeline: AES-128 HLS + Key Guard + Lease ───
function requireHlsAuth({ checkActiveStream = true } = {}) {
  return async (req, res, next) => {
    const videoId = String(req.params.videoId ?? '');
    if (!SAFE_VIDEO_ID.test(videoId)) return res.status(400).end();

    const session = verifyJwt(req.cookies?.[SESSION_COOKIE] ?? '', 'session');
    const hls = verifyJwt(String(req.query.token ?? ''), 'hls');
    if (
      !session ||
      !hls ||
      session.uid !== hls.uid ||
      session.jkt !== hls.jkt ||
      hls.vid !== videoId
    ) {
      return res.status(401).json({ error: 'طلب بث غير مصرح به.', code: 'SESSION_REQUIRED' });
    }

    if (checkActiveStream) {
      const user = await db.findUserById(session.uid);
      if (!user || user.session_version !== session.ver || user.is_banned) {
        return res.status(401).json({ error: 'انتهت الجلسة.', code: 'SESSION_REQUIRED' });
      }
      if (user.requires_step_up && user.role !== 'admin') {
        return res.status(403).json({ error: 'مطلوب تأكيد الهوية.', code: 'STEP_UP_REQUIRED' });
      }
      const device = await db.findDevice(user.id, session.jkt);
      if (!device || device.id !== hls.dev) {
        return res.status(401).json({ error: 'تمت إزالة الجهاز.', code: 'SESSION_REQUIRED' });
      }
      if (user.active_stream_id !== hls.sid) {
        return res.status(409).json({
          error: 'تم إيقاف البث لأن حسابك بدأ المشاهدة على جهاز آخر.',
          code: 'STREAM_TAKEN_OVER',
        });
      }
    }

    req.hls = hls;
    next();
  };
}

app.post('/api/lessons/:videoId/play', requireSession(), async (req, res) => {
  const videoId = String(req.params.videoId ?? '');
  if (!SAFE_VIDEO_ID.test(videoId)) {
    return res.status(400).json({ error: 'معرف الدرس غير صالح.' });
  }
  const user = req.user;

  if (!(await db.hasEntitlement(user.id, videoId))) {
    return res.status(403).json({ error: 'أنت غير مشترك في هذا الكورس.', code: 'NOT_ENROLLED' });
  }

  const video = await db.getVideoById(videoId);
  if (!video) {
    return res.status(404).json({ error: 'الفيديو غير موجود.' });
  }

  const otherDeviceWasLive =
    user.active_stream_device_id &&
    user.active_stream_device_id !== req.device.id &&
    user.heartbeat_age_s !== null &&
    user.heartbeat_age_s < POLICY.TAKEOVER_WINDOW_S;

  const streamId = crypto.randomUUID();
  await db.claimStream(user.id, req.device.id, streamId);
  if (otherDeviceWasLive) {
    await risk.record(user.id, 'stream_takeover', req.ip, { videoId });
  }

  const hlsToken = jwt.sign(
    {
      typ: 'hls',
      uid: user.id,
      dev: req.device.id,
      jkt: req.device.jwk_thumbprint,
      vid: videoId,
      sid: streamId,
    },
    JWT_SECRET,
    { algorithm: 'HS256', expiresIn: POLICY.HLS_TOKEN_TTL_S }
  );

  res.json({
    streamId,
    videoTitle: video.title,
    watermark: `MZTRADER • ID: ${user.watermark_code}`,
    manifestUrl: `/api/hls/${encodeURIComponent(videoId)}/index.m3u8?token=${encodeURIComponent(hlsToken)}`,
  });
});

/**
 * Helper that rewrites an external HLS playlist (master or media) so:
 * - Master playlists route variant streams through `/api/hls/:videoId/variant.m3u8`
 * - Media playlists inject `#EXT-X-KEY:METHOD=AES-128,URI="/api/hls/:videoId/key?token=...",IV=0x...`
 *   and route `.ts` segments through `/api/hls/:videoId/seg.ts` (which encrypts segments with AES-128-CBC
 *   using the video's 16-byte DB key and enforces `active_stream_id === hls.sid`).
 */
function signStreamUrl(videoId, encodedUrl) {
  return crypto.createHmac('sha256', JWT_SECRET).update(`${videoId}:${encodedUrl}`).digest('base64url');
}

function verifyStreamUrl(videoId, encodedUrl, sig) {
  if (typeof sig !== 'string' || !sig) return false;
  const expected = signStreamUrl(videoId, encodedUrl);
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function rewriteHlsManifest(rawText, baseUrl, video, token) {
  const tokenParam = `token=${encodeURIComponent(token)}`;
  const keyUri = `/api/hls/${encodeURIComponent(video.id)}/key?${tokenParam}`;
  const isMaster = rawText.includes('#EXT-X-STREAM-INF');
  const alreadyHasKey = rawText.includes('#EXT-X-KEY:');

  const lines = rawText.split(/\r?\n/);
  const out = [];
  let keyInjected = false;

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) {
      out.push(line);
      continue;
    }

    if (trimmed.startsWith('#EXT-X-KEY:')) {
      out.push(trimmed.replace(/URI="[^"]+"/, `URI="${keyUri}"`));
      keyInjected = true;
      continue;
    }

    if (!isMaster && !alreadyHasKey && !keyInjected && trimmed.startsWith('#EXTINF:')) {
      out.push(`#EXT-X-KEY:METHOD=AES-128,URI="${keyUri}",IV=0x${video.aes_iv_hex}`);
      keyInjected = true;
    }

    if (trimmed.startsWith('#')) {
      out.push(line);
      continue;
    }

    const resolvedUrl = new URL(trimmed, baseUrl).toString();
    const encodedUrl = Buffer.from(resolvedUrl, 'utf8').toString('base64url');
    const sig = signStreamUrl(video.id, encodedUrl);

    if (isMaster || resolvedUrl.includes('.m3u8')) {
      out.push(`/api/hls/${encodeURIComponent(video.id)}/variant.m3u8?u=${encodedUrl}&sig=${sig}&${tokenParam}`);
    } else if (alreadyHasKey) {
      // External CDN (e.g. Cloudflare R2) segments are already AES-128 encrypted; stream directly from CDN
      out.push(resolvedUrl);
    } else {
      // Encrypt external segments on the fly with the video's 16-byte AES-128 key
      out.push(`/api/hls/${encodeURIComponent(video.id)}/seg.ts?u=${encodedUrl}&sig=${sig}&${tokenParam}`);
    }
  }

  return out.join('\n');
}

function fetchUpstreamOnce(targetUrl, redirects = 0) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(targetUrl);
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return reject(new Error('Unsupported upstream protocol'));
    }
    const client = parsed.protocol === 'https:' ? https : http;
    const req = client.get(
      parsed,
      {
        headers: { 'User-Agent': 'MZTRADER-Stream/1.0' },
        autoSelectFamily: true,
        autoSelectFamilyAttemptTimeout: 300,
        timeout: 7000,
      },
      (res) => {
        const status = res.statusCode ?? 502;
        if ([301, 302, 303, 307, 308].includes(status) && res.headers.location && redirects < 5) {
          res.resume();
          const nextUrl = new URL(res.headers.location, parsed).toString();
          fetchUpstreamOnce(nextUrl, redirects + 1).then(resolve, reject);
          return;
        }
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => {
          const buf = Buffer.concat(chunks);
          resolve({
            ok: status >= 200 && status < 300,
            status,
            text: async () => buf.toString('utf8'),
            arrayBuffer: async () => buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength),
          });
        });
        res.on('error', reject);
      },
    );
    req.on('timeout', () => req.destroy(new Error('Upstream request timed out')));
    req.on('error', reject);
  });
}

async function fetchUpstream(targetUrl) {
  let lastErr;
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      return await fetchUpstreamOnce(targetUrl);
    } catch (err) {
      lastErr = err;
    }
  }
  throw lastErr;
}

app.get('/api/hls/:videoId/index.m3u8', requireHlsAuth({ checkActiveStream: true }), async (req, res) => {
  const video = await db.getVideoById(req.params.videoId);
  if (!video) return res.status(404).end();

  try {
    const upstream = await fetchUpstream(video.video_url);
    if (!upstream.ok) return res.status(502).end();
    const raw = await upstream.text();
    const rewritten = rewriteHlsManifest(raw, video.video_url, video, String(req.query.token));
    res.set({
      'Content-Type': 'application/vnd.apple.mpegurl',
      'Cache-Control': 'no-store',
    });
    res.send(rewritten);
  } catch {
    res.status(502).end();
  }
});

app.get('/api/hls/:videoId/variant.m3u8', requireHlsAuth({ checkActiveStream: true }), async (req, res) => {
  const video = await db.getVideoById(req.params.videoId);
  if (!video) return res.status(404).end();

  const encodedUrl = String(req.query.u ?? '');
  if (!verifyStreamUrl(video.id, encodedUrl, String(req.query.sig ?? ''))) {
    return res.status(403).end();
  }

  let targetUrl;
  try {
    targetUrl = Buffer.from(encodedUrl, 'base64url').toString('utf8');
    const parsed = new URL(targetUrl);
    if (!['http:', 'https:'].includes(parsed.protocol)) return res.status(400).end();
  } catch {
    return res.status(400).end();
  }

  try {
    const upstream = await fetchUpstream(targetUrl);
    if (!upstream.ok) return res.status(502).end();
    const raw = await upstream.text();
    const rewritten = rewriteHlsManifest(raw, targetUrl, video, String(req.query.token));
    res.set({
      'Content-Type': 'application/vnd.apple.mpegurl',
      'Cache-Control': 'no-store',
    });
    res.send(rewritten);
  } catch {
    res.status(502).end();
  }
});

// Serves the 16-byte binary AES-128 key from DB ONLY if this device holds the active stream lease
app.get('/api/hls/:videoId/key', requireHlsAuth({ checkActiveStream: true }), async (req, res) => {
  const video = await db.getVideoById(req.params.videoId);
  if (!video || !video.aes_key_hex) return res.status(404).end();

  const keyBytes = Buffer.from(video.aes_key_hex, 'hex');
  if (keyBytes.length !== 16) return res.status(500).end();

  res.set({
    'Content-Type': 'application/octet-stream',
    'Cache-Control': 'no-store',
  });
  res.send(keyBytes);
});

// Serves AES-128-CBC encrypted .ts segments while verifying the active stream lease
app.get('/api/hls/:videoId/seg.ts', requireHlsAuth({ checkActiveStream: true }), async (req, res) => {
  const video = await db.getVideoById(req.params.videoId);
  if (!video) return res.status(404).end();

  const encodedUrl = String(req.query.u ?? '');
  if (!verifyStreamUrl(video.id, encodedUrl, String(req.query.sig ?? ''))) {
    return res.status(403).end();
  }

  let targetUrl;
  try {
    targetUrl = Buffer.from(encodedUrl, 'base64url').toString('utf8');
    const parsed = new URL(targetUrl);
    if (!['http:', 'https:'].includes(parsed.protocol)) return res.status(400).end();
  } catch {
    return res.status(400).end();
  }

  try {
    const upstream = await fetchUpstream(targetUrl);
    if (!upstream.ok) return res.status(502).end();
    const plainBuf = Buffer.from(await upstream.arrayBuffer());

    const keyBuf = Buffer.from(video.aes_key_hex, 'hex');
    const ivBuf = Buffer.from(video.aes_iv_hex, 'hex');
    const cipher = crypto.createCipheriv('aes-128-cbc', keyBuf, ivBuf);
    const encryptedBuf = Buffer.concat([cipher.update(plainBuf), cipher.final()]);

    res.set({
      'Content-Type': 'video/mp2t',
      'Cache-Control': 'no-store',
    });
    res.send(encryptedBuf);
  } catch {
    res.status(502).end();
  }
});

app.post('/api/stream/heartbeat', requireSession(), async (req, res) => {
  const { streamId } = req.body ?? {};
  if (typeof streamId !== 'string') return res.status(400).json({ error: 'streamId required.' });

  if (!(await db.heartbeat(req.user.id, streamId))) {
    return res.status(409).json({
      error: 'تم إيقاف البث لأن حسابك بدأ المشاهدة على جهاز آخر.',
      code: 'STREAM_TAKEN_OVER',
    });
  }
  res.status(204).end();
});

// ── 10. Admin Control Center Routes ────────────────────────────────
app.get('/api/admin/overview', requireSession({ allowStepUp: true, requireAdmin: true }), async (_req, res) => {
  const data = await db.getAdminOverview();
  res.json(data);
});

app.post('/api/admin/users/:id/toggle-enroll', requireSession({ allowStepUp: true, requireAdmin: true }), async (req, res) => {
  await db.adminToggleEnroll(Number(req.params.id), Boolean(req.body?.enroll));
  res.json({ ok: true });
});

app.post('/api/admin/codes/generate', requireSession({ allowStepUp: true, requireAdmin: true }), async (req, res) => {
  const codes = await db.adminGenerateCodes(Number(req.body?.count ?? 5));
  res.json({ ok: true, codes });
});

app.post('/api/admin/courses/module', requireSession({ allowStepUp: true, requireAdmin: true }), async (req, res) => {
  if (!req.body?.title) return res.status(400).json({ error: 'عنوان الوحدة مطلوب.' });
  const id = await db.adminCreateModule(req.body.title);
  res.json({ ok: true, id });
});

app.post('/api/admin/courses/video', requireSession({ allowStepUp: true, requireAdmin: true }), async (req, res) => {
  const { id, moduleId, title, description, duration, videoUrl, aesKeyHex, attachmentName } = req.body ?? {};
  if (!moduleId || !title || !videoUrl) {
    return res.status(400).json({ error: 'الوحدة، عنوان الدرس، ورابط البث الخارجي (.m3u8) مطلوبة.' });
  }
  const slug = await db.adminSaveVideo({ id, moduleId, title, description, duration, videoUrl, aesKeyHex, attachmentName });
  res.json({ ok: true, id: slug });
});

app.get('/api/admin/leak-lookup', requireSession({ allowStepUp: true, requireAdmin: true }), async (req, res) => {
  const result = await db.adminLookupByWatermark(req.query.code);
  if (!result) return res.status(404).json({ error: 'لم يتم العثور على أي مشترك بهذا الكود المائي.' });
  res.json(result);
});

app.post('/api/admin/users/:id/clear-risk', requireSession({ allowStepUp: true, requireAdmin: true }), async (req, res) => {
  await db.adminClearRisk(Number(req.params.id));
  res.json({ ok: true });
});

app.post('/api/admin/users/:id/reset-quota', requireSession({ allowStepUp: true, requireAdmin: true }), async (req, res) => {
  await db.adminResetDeviceQuota(Number(req.params.id));
  res.json({ ok: true });
});

app.post('/api/admin/users/:id/logout-all', requireSession({ allowStepUp: true, requireAdmin: true }), async (req, res) => {
  await db.adminForceLogoutEverywhere(Number(req.params.id));
  res.json({ ok: true });
});

app.post('/api/admin/users/:id/ban', requireSession({ allowStepUp: true, requireAdmin: true }), async (req, res) => {
  await db.adminSetBan(Number(req.params.id), Boolean(req.body?.isBanned), req.body?.reason);
  res.json({ ok: true });
});

app.delete('/api/admin/users/:id', requireSession({ allowStepUp: true, requireAdmin: true }), async (req, res) => {
  const userId = Number(req.params.id);
  if (!Number.isInteger(userId) || userId <= 0) {
    return res.status(400).json({ error: 'معرف المستخدم غير صالح.' });
  }
  const deleted = await db.adminDeleteUser(userId);
  if (!deleted) {
    return res.status(400).json({ error: 'لا يمكن حذف حساب المدير أو لم يتم العثور على الحساب.' });
  }
  res.json({ ok: true });
});

app.delete('/api/admin/codes/:id', requireSession({ allowStepUp: true, requireAdmin: true }), async (req, res) => {
  const codeId = Number(req.params.id);
  if (!Number.isInteger(codeId) || codeId <= 0) {
    return res.status(400).json({ error: 'معرف الكود غير صالح.' });
  }
  const deleted = await db.adminDeleteCode(codeId);
  if (!deleted) {
    return res.status(400).json({ error: 'لا يمكن حذف كود مُستخدم مسبقاً أو غير موجود.' });
  }
  res.json({ ok: true });
});

// ── 11. Frontend Page & Health Routes ──────────────────────────────
app.get('/health', (_req, res) => {
  res.json({ status: 'ok' });
});

app.get('/portal', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'portal.html'));
});

app.get('/admin', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// ── 12. Error Handler, Lazy Housekeeping & Startup ─────────────────
app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: 'حدث خطأ غير متوقع في الخادم. يرجى المحاولة مرة أخرى.' });
});

const HOST = process.env.HOST || '0.0.0.0';

db.initDb()
  .then(() => {
    app.listen(PORT, HOST, () => {
      console.log(`MZTRADER server listening on http://${HOST}:${PORT} (DB: ${db.DB_LABEL})`);
    });
  })
  .catch((err) => {
    console.error('Failed to initialize MZTRADER DB:', err);
    process.exit(1);
  });
