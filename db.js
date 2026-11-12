'use strict';
/**
 * db.js: Tri-mode database engine for MZTRADER.
 * - PostgreSQL Mode (Layerbase PostgreSQL / Neon / Supabase): Activated when DATABASE_URL starts with postgres:// or postgresql:// (or DB_ENGINE=postgres).
 * - MySQL/MariaDB Mode: Activated when DATABASE_URL starts with mysql:// or mariadb:// (or DB_HOST is set without postgres).
 * - Local Mode (SQLite): Activated automatically when no external DB env vars are set.
 */
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const argon2 = require('argon2');

const CODE_SECRET = process.env.CODE_SECRET || 'mztrader-default-hmac-code-secret-key-2026-secure';
const hashCode = (code) => crypto.createHmac('sha256', CODE_SECRET).update(String(code)).digest('hex');

function detectDbEngine() {
  const explicit = (process.env.DB_ENGINE || '').trim().toLowerCase();
  if (explicit === 'postgres' || explicit === 'postgresql' || explicit === 'pg') return 'postgres';
  if (explicit === 'mysql' || explicit === 'mariadb') return 'mysql';

  const rawUrl = (process.env.DATABASE_URL || '').trim();
  if (rawUrl) {
    const proto = new URL(rawUrl).protocol.replace(':', '').toLowerCase();
    if (proto === 'postgres' || proto === 'postgresql') return 'postgres';
    return 'mysql';
  }
  if (process.env.DB_HOST) {
    return Number(process.env.DB_PORT) === 5432 ? 'postgres' : 'mysql';
  }
  return 'sqlite';
}

const DB_ENGINE = detectDbEngine();
const USE_MYSQL = DB_ENGINE === 'mysql';
const DB_LABEL = DB_ENGINE === 'postgres' ? 'Layerbase PostgreSQL' : DB_ENGINE === 'mysql' ? 'MySQL' : 'Local SQLite';

let pgPool = null;
let mysqlPool = null;
let sqlite = null;

if (DB_ENGINE === 'postgres') {
  const { Pool, types } = require('pg');
  // Parse INT8 (BIGINT / COUNT / SUM / BIGSERIAL) as JS numbers for parity with SQLite & MySQL
  types.setTypeParser(20, (val) => (val === null ? null : Number(val)));

  let poolConfig;
  if (process.env.DATABASE_URL) {
    const dbUrl = new URL(process.env.DATABASE_URL);
    const sslMode = (dbUrl.searchParams.get('sslmode') || dbUrl.searchParams.get('ssl-mode') || '').toLowerCase();
    const disableSsl = process.env.DB_SSL === 'false' || sslMode === 'disable' || sslMode === 'disabled';
    const strictSsl = process.env.DB_SSL_STRICT === 'true' || sslMode === 'verify-full';
    poolConfig = {
      host: dbUrl.hostname,
      port: Number(dbUrl.port || 5432),
      user: decodeURIComponent(dbUrl.username),
      password: decodeURIComponent(dbUrl.password),
      database: dbUrl.pathname.replace(/^\//, ''),
      ssl: disableSsl ? false : { rejectUnauthorized: strictSsl },
    };
  } else {
    const disableSsl = process.env.DB_SSL === 'false';
    const strictSsl = process.env.DB_SSL_STRICT === 'true';
    poolConfig = {
      host: process.env.DB_HOST,
      port: Number(process.env.DB_PORT ?? 5432),
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME,
      ssl: disableSsl ? false : { rejectUnauthorized: strictSsl },
    };
  }

  pgPool = new Pool({
    ...poolConfig,
    max: 12,                      // Safe margin under Layerbase's 20-connection limit
    idleTimeoutMillis: 60000,     // Releases idle connections so Layerbase can sleep on idle
    connectionTimeoutMillis: 15000,
  });
  pgPool.on('error', (err) => {
    console.error('PostgreSQL idle client error:', err.message);
  });
} else if (DB_ENGINE === 'mysql') {
  const mysql = require('mysql2/promise');
  const sslOpt = process.env.DB_SSL === 'false'
    ? undefined
    : { rejectUnauthorized: process.env.DB_SSL_STRICT === 'true' };

  let poolConfig;
  if (process.env.DATABASE_URL) {
    const dbUrl = new URL(process.env.DATABASE_URL);
    poolConfig = {
      host: dbUrl.hostname,
      port: Number(dbUrl.port || 3306),
      user: decodeURIComponent(dbUrl.username),
      password: decodeURIComponent(dbUrl.password),
      database: dbUrl.pathname.replace(/^\//, ''),
      ssl: dbUrl.searchParams.get('ssl-mode') === 'DISABLED' ? undefined : sslOpt,
      waitForConnections: true,
      connectionLimit: 12, // Safe margin under Layerbase's 20-connection limit
      maxIdle: 2,
      idleTimeout: 60000,  // Releases idle connections so DB can sleep on idle
      enableKeepAlive: true,
    };
  } else {
    poolConfig = {
      host: process.env.DB_HOST,
      port: Number(process.env.DB_PORT ?? 3306),
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME,
      ssl: sslOpt,
      waitForConnections: true,
      connectionLimit: 12,
      maxIdle: 2,
      idleTimeout: 60000,
      enableKeepAlive: true,
    };
  }
  mysqlPool = mysql.createPool(poolConfig);
} else {
  const { DatabaseSync } = require('node:sqlite');
  const DATA_DIR = path.join(__dirname, 'data');
  fs.mkdirSync(DATA_DIR, { recursive: true });
  sqlite = new DatabaseSync(path.join(DATA_DIR, 'mztrader.sqlite'));
  sqlite.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;');
}

// ── Unified Query & Transaction Helpers ────────────────────────────
const SQL_TIME_EXPRS = {
  postgres: {
    nowExpr: 'NOW()',
    minus5Min: "NOW() - INTERVAL '5 minutes'",
    plus10Min: "NOW() + INTERVAL '10 minutes'",
    minus1Day: "NOW() - INTERVAL '1 day'",
    minus7Days: "NOW() - INTERVAL '7 days'",
    minus30Days: "NOW() - INTERVAL '30 days'",
    minus90Days: "NOW() - INTERVAL '90 days'",
  },
  mysql: {
    nowExpr: 'NOW()',
    minus5Min: 'NOW() - INTERVAL 5 MINUTE',
    plus10Min: 'NOW() + INTERVAL 10 MINUTE',
    minus1Day: 'NOW() - INTERVAL 1 DAY',
    minus7Days: 'NOW() - INTERVAL 7 DAY',
    minus30Days: 'NOW() - INTERVAL 30 DAY',
    minus90Days: 'NOW() - INTERVAL 90 DAY',
  },
  sqlite: {
    nowExpr: "datetime('now')",
    minus5Min: "datetime('now', '-5 minutes')",
    plus10Min: "datetime('now', '+10 minutes')",
    minus1Day: "datetime('now', '-1 day')",
    minus7Days: "datetime('now', '-7 days')",
    minus30Days: "datetime('now', '-30 days')",
    minus90Days: "datetime('now', '-90 days')",
  },
};
const { nowExpr, minus5Min, plus10Min, minus1Day, minus7Days, minus30Days, minus90Days } = SQL_TIME_EXPRS[DB_ENGINE];

function toPgSql(sql) {
  let out = '';
  let idx = 0;
  let inQuote = false;
  for (let i = 0; i < sql.length; i++) {
    const ch = sql[i];
    if (ch === "'") {
      out += ch;
      if (inQuote && sql[i + 1] === "'") {
        out += "'";
        i++;
      } else {
        inQuote = !inQuote;
      }
      continue;
    }
    if (ch === '?' && !inQuote) {
      out += `$${++idx}`;
    } else {
      out += ch;
    }
  }
  return out;
}

function buildInsertIgnoreSql(rest) {
  if (DB_ENGINE === 'postgres') return `INSERT INTO ${rest} ON CONFLICT DO NOTHING`;
  if (DB_ENGINE === 'mysql') return `INSERT IGNORE INTO ${rest}`;
  return `INSERT OR IGNORE INTO ${rest}`;
}

const SERIAL_ID_INSERT_RE = /^\s*INSERT\s+INTO\s+(users|user_devices|device_changes|email_codes|security_events|courses|modules|activation_codes)\b/i;

async function queryAll(sql, params = [], conn = null) {
  if (DB_ENGINE === 'postgres') {
    const res = await (conn || pgPool).query(toPgSql(sql), params);
    return res.rows;
  }
  if (DB_ENGINE === 'mysql') {
    const [rows] = await (conn || mysqlPool).execute(sql, params);
    return rows;
  }
  return sqlite.prepare(sql).all(...params);
}

async function queryOne(sql, params = [], conn = null) {
  const rows = await queryAll(sql, params, conn);
  return rows[0] ?? null;
}

async function execRun(sql, params = [], conn = null) {
  if (DB_ENGINE === 'postgres') {
    let pgSql = toPgSql(sql);
    const wantsId = SERIAL_ID_INSERT_RE.test(pgSql) && !/\bRETURNING\b/i.test(pgSql) && !/\bON\s+CONFLICT\b/i.test(pgSql);
    if (wantsId) pgSql = `${pgSql.trim().replace(/;$/, '')} RETURNING id`;
    const res = await (conn || pgPool).query(pgSql, params);
    return {
      changes: Number(res.rowCount ?? 0),
      lastInsertRowid: res.rows[0]?.id !== undefined ? Number(res.rows[0].id) : 0,
    };
  }
  if (DB_ENGINE === 'mysql') {
    const [res] = await (conn || mysqlPool).execute(sql, params);
    return { changes: res.affectedRows, lastInsertRowid: res.insertId };
  }
  const res = sqlite.prepare(sql).run(...params);
  return { changes: Number(res.changes), lastInsertRowid: Number(res.lastInsertRowid) };
}

async function withTx(fn) {
  if (DB_ENGINE === 'postgres') {
    const client = await pgPool.connect();
    try {
      await client.query('BEGIN');
      const result = await fn(client);
      await client.query('COMMIT');
      return result;
    } catch (err) {
      try { await client.query('ROLLBACK'); } catch {}
      throw err;
    } finally {
      client.release();
    }
  }
  if (DB_ENGINE === 'mysql') {
    const conn = await mysqlPool.getConnection();
    try {
      await conn.beginTransaction();
      const result = await fn(conn);
      await conn.commit();
      return result;
    } catch (err) {
      await conn.rollback();
      throw err;
    } finally {
      conn.release();
    }
  }

  sqlite.exec('BEGIN IMMEDIATE');
  try {
    const result = await fn(null);
    sqlite.exec('COMMIT');
    return result;
  } catch (err) {
    try { sqlite.exec('ROLLBACK'); } catch {}
    throw err;
  }
}

function generateWatermarkCode() {
  const digits = crypto.randomInt(1000, 9999);
  const letters = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
  const suffix = letters[crypto.randomInt(0, letters.length)];
  return `MZT-${digits}-${suffix}`;
}

async function uniqueWatermarkCode(conn = null) {
  for (let i = 0; i < 20; i++) {
    const code = generateWatermarkCode();
    const exists = await queryOne('SELECT 1 FROM users WHERE watermark_code = ? LIMIT 1', [code], conn);
    if (!exists) return code;
  }
  return `MZT-${Date.now().toString().slice(-4)}-X`;
}

// ── Schema & Seed Initialization ───────────────────────────────────
const MYSQL_SCHEMA_STATEMENTS = [
  `CREATE TABLE IF NOT EXISTS users (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    full_name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    phone VARCHAR(100) NOT NULL DEFAULT '',
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'student',
    watermark_code VARCHAR(32) NOT NULL UNIQUE,
    session_version INT NOT NULL DEFAULT 1,
    active_stream_id VARCHAR(64) NULL,
    active_stream_device_id BIGINT NULL,
    last_heartbeat_at DATETIME NULL,
    last_country CHAR(2) NULL,
    last_country_at DATETIME NULL,
    requires_step_up TINYINT(1) NOT NULL DEFAULT 0,
    needs_review TINYINT(1) NOT NULL DEFAULT 0,
    is_banned TINYINT(1) NOT NULL DEFAULT 0,
    ban_reason VARCHAR(255) NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`,
  `CREATE TABLE IF NOT EXISTS user_devices (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    user_id BIGINT NOT NULL,
    device_label VARCHAR(100) NOT NULL,
    jwk_thumbprint CHAR(43) NOT NULL,
    public_key_jwk TEXT NOT NULL,
    last_ip VARCHAR(45) NULL,
    last_seen_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_user_device (user_id, jwk_thumbprint),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  )`,
  `CREATE TABLE IF NOT EXISTS device_changes (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    user_id BIGINT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_user_time (user_id, created_at),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  )`,
  `CREATE TABLE IF NOT EXISTS email_codes (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    user_id BIGINT NOT NULL,
    purpose VARCHAR(32) NOT NULL,
    jwk_thumbprint CHAR(43) NOT NULL,
    code_hash CHAR(64) NOT NULL,
    raw_code_preview VARCHAR(16) NULL,
    attempts TINYINT NOT NULL DEFAULT 0,
    expires_at DATETIME NOT NULL,
    consumed_at DATETIME NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_lookup (user_id, purpose, jwk_thumbprint),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  )`,
  `CREATE TABLE IF NOT EXISTS security_events (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    user_id BIGINT NOT NULL,
    type VARCHAR(40) NOT NULL,
    points INT NOT NULL DEFAULT 0,
    ip VARCHAR(45) NULL,
    meta TEXT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_user_time (user_id, created_at),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  )`,
  `CREATE TABLE IF NOT EXISTS dpop_jti_cache (
    jti VARCHAR(64) PRIMARY KEY,
    expires_at BIGINT NOT NULL,
    INDEX idx_expires (expires_at)
  )`,
  `CREATE TABLE IF NOT EXISTS courses (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`,
  `CREATE TABLE IF NOT EXISTS modules (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    course_id BIGINT NOT NULL,
    title VARCHAR(255) NOT NULL,
    sort_order INT NOT NULL DEFAULT 1,
    FOREIGN KEY (course_id) REFERENCES courses(id) ON DELETE CASCADE
  )`,
  `CREATE TABLE IF NOT EXISTS videos (
    id VARCHAR(64) PRIMARY KEY,
    course_id BIGINT NOT NULL,
    module_id BIGINT NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    duration VARCHAR(32) NOT NULL DEFAULT '12:00',
    video_url TEXT NOT NULL,
    aes_key_hex CHAR(32) NOT NULL,
    aes_iv_hex CHAR(32) NOT NULL,
    attachment_name VARCHAR(255) NULL,
    attachment_url VARCHAR(255) NULL,
    sort_order INT NOT NULL DEFAULT 1,
    FOREIGN KEY (course_id) REFERENCES courses(id) ON DELETE CASCADE,
    FOREIGN KEY (module_id) REFERENCES modules(id) ON DELETE CASCADE
  )`,
  `CREATE TABLE IF NOT EXISTS lesson_progress (
    user_id BIGINT NOT NULL,
    video_id VARCHAR(64) NOT NULL,
    completed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, video_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (video_id) REFERENCES videos(id) ON DELETE CASCADE
  )`,
  `CREATE TABLE IF NOT EXISTS enrollments (
    user_id BIGINT NOT NULL,
    course_id BIGINT NOT NULL,
    activated_via VARCHAR(64) NOT NULL DEFAULT 'admin',
    expires_at DATETIME NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, course_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (course_id) REFERENCES courses(id) ON DELETE CASCADE
  )`,
  `CREATE TABLE IF NOT EXISTS activation_codes (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    code VARCHAR(64) NOT NULL UNIQUE,
    course_id BIGINT NOT NULL DEFAULT 1,
    used_by_user_id BIGINT NULL,
    used_at DATETIME NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (course_id) REFERENCES courses(id) ON DELETE CASCADE,
    FOREIGN KEY (used_by_user_id) REFERENCES users(id) ON DELETE SET NULL
  )`,
];

const POSTGRES_SCHEMA_STATEMENTS = [
  `CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    full_name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    phone TEXT NOT NULL DEFAULT '',
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'student',
    watermark_code TEXT NOT NULL UNIQUE,
    session_version INTEGER NOT NULL DEFAULT 1,
    active_stream_id TEXT NULL,
    active_stream_device_id BIGINT NULL,
    last_heartbeat_at TIMESTAMPTZ NULL,
    last_country CHAR(2) NULL,
    last_country_at TIMESTAMPTZ NULL,
    requires_step_up SMALLINT NOT NULL DEFAULT 0,
    needs_review SMALLINT NOT NULL DEFAULT 0,
    is_banned SMALLINT NOT NULL DEFAULT 0,
    ban_reason TEXT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`,
  `CREATE TABLE IF NOT EXISTS user_devices (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_label TEXT NOT NULL,
    jwk_thumbprint TEXT NOT NULL,
    public_key_jwk TEXT NOT NULL,
    last_ip TEXT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (user_id, jwk_thumbprint)
  )`,
  `CREATE TABLE IF NOT EXISTS device_changes (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`,
  `CREATE INDEX IF NOT EXISTS idx_device_changes_user_time ON device_changes (user_id, created_at)`,
  `CREATE TABLE IF NOT EXISTS email_codes (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    purpose TEXT NOT NULL,
    jwk_thumbprint TEXT NOT NULL,
    code_hash TEXT NOT NULL,
    raw_code_preview TEXT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`,
  `CREATE INDEX IF NOT EXISTS idx_email_codes_lookup ON email_codes (user_id, purpose, jwk_thumbprint)`,
  `CREATE TABLE IF NOT EXISTS security_events (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type TEXT NOT NULL,
    points INTEGER NOT NULL DEFAULT 0,
    ip TEXT NULL,
    meta TEXT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`,
  `CREATE INDEX IF NOT EXISTS idx_security_events_user_time ON security_events (user_id, created_at)`,
  `CREATE TABLE IF NOT EXISTS dpop_jti_cache (
    jti TEXT PRIMARY KEY,
    expires_at BIGINT NOT NULL
  )`,
  `CREATE INDEX IF NOT EXISTS idx_dpop_jti_expires ON dpop_jti_cache (expires_at)`,
  `CREATE TABLE IF NOT EXISTS courses (
    id BIGSERIAL PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`,
  `CREATE TABLE IF NOT EXISTS modules (
    id BIGSERIAL PRIMARY KEY,
    course_id BIGINT NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    sort_order INTEGER NOT NULL DEFAULT 1
  )`,
  `CREATE TABLE IF NOT EXISTS videos (
    id TEXT PRIMARY KEY,
    course_id BIGINT NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
    module_id BIGINT NOT NULL REFERENCES modules(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    duration TEXT NOT NULL DEFAULT '12:00',
    video_url TEXT NOT NULL,
    aes_key_hex CHAR(32) NOT NULL,
    aes_iv_hex CHAR(32) NOT NULL,
    attachment_name TEXT NULL,
    attachment_url TEXT NULL,
    sort_order INTEGER NOT NULL DEFAULT 1
  )`,
  `CREATE TABLE IF NOT EXISTS lesson_progress (
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    video_id TEXT NOT NULL REFERENCES videos(id) ON DELETE CASCADE,
    completed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, video_id)
  )`,
  `CREATE TABLE IF NOT EXISTS enrollments (
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    course_id BIGINT NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
    activated_via TEXT NOT NULL DEFAULT 'admin',
    expires_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, course_id)
  )`,
  `CREATE TABLE IF NOT EXISTS activation_codes (
    id BIGSERIAL PRIMARY KEY,
    code TEXT NOT NULL UNIQUE,
    course_id BIGINT NOT NULL DEFAULT 1 REFERENCES courses(id) ON DELETE CASCADE,
    used_by_user_id BIGINT NULL REFERENCES users(id) ON DELETE SET NULL,
    used_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`,
];

async function initRemoteSchema(stmts, runner) {
  let lastErr;
  for (let attempt = 1; attempt <= 4; attempt++) {
    try {
      for (const stmt of stmts) {
        await runner.query(stmt);
      }
      return;
    } catch (err) {
      lastErr = err;
      console.warn(`DB init attempt ${attempt}/4 failed (${err.message}); retrying in 2s...`);
      await new Promise((r) => setTimeout(r, 2000));
    }
  }
  throw lastErr;
}

async function ensureCourseSeeded() {
  const existingCourse = await queryOne('SELECT id FROM courses ORDER BY id ASC LIMIT 1');
  if (existingCourse) return Number(existingCourse.id);

  return withTx(async (conn) => {
    const courseRes = await execRun(
      'INSERT INTO courses (title, description) VALUES (?, ?)',
      [
        'احتراف التداول والتحليل الفني - MZTRADER',
        'برنامج تدريبي متكامل يغطي هيكلة السوق، مناطق السيولة، إدارة المخاطر الصارمة، واستراتيجيات الدخول عالية الدقة.',
      ],
      conn
    );
    const courseId = courseRes.lastInsertRowid;

    const m1 = (await execRun('INSERT INTO modules (course_id, title, sort_order) VALUES (?, ?, ?)', [courseId, 'الوحدة الأولى: أساسيات هيكلة السوق وحركة السعر (Market Structure)', 1], conn)).lastInsertRowid;
    const m2 = (await execRun('INSERT INTO modules (course_id, title, sort_order) VALUES (?, ?, ?)', [courseId, 'الوحدة الثانية: مناطق السيولة ومفاهيم الأموال الذكية (SMC & Liquidity)', 2], conn)).lastInsertRowid;
    const m3 = (await execRun('INSERT INTO modules (course_id, title, sort_order) VALUES (?, ?, ?)', [courseId, 'الوحدة الثالثة: إدارة المخاطر وبناء خطة التداول الاحترافية', 3], conn)).lastInsertRowid;

    const sampleHls = 'https://demo.unified-streaming.com/k8s/features/stable/video/tears-of-steel/tears-of-steel.ism/.m3u8';
    const lessons = [
      { id: 'lesson-01', moduleId: m1, title: '1. قراءة الاتجاه العام وتحديد القمم والقيعان الرئيسية (Swing Structure)', description: 'في هذا الدرس نتعلم كيفية تحديد الاتجاه الحقيقي للسوق على الفريمات الكبيرة وتجنب الدخول عكس السيولة المؤسسية، مع أمثلة تطبيقية مباشرة على الشارت.', duration: '14:20', attachmentName: 'ملخص_هيكلة_السوق_MZTRADER.pdf', sortOrder: 1 },
      { id: 'lesson-02', moduleId: m1, title: '2. الفرق بين كسر الهيكلة الحقيقي (BOS) وتغير الاتجاه (CHoCH)', description: 'شرح عملي دقيق للفرق بين استمرار الاتجاه (Break of Structure) وأول إشارة انعكاس حقيقية (Change of Character) مع شروط الإغلاق المعتمدة.', duration: '18:45', attachmentName: 'شروط_BOS_و_CHoCH_MZTRADER.pdf', sortOrder: 2 },
      { id: 'lesson-03', moduleId: m2, title: '3. خريطة السيولة: أين تتمركز أوامر وقف الخسارة؟ (Buy/Sell Side Liquidity)', description: 'كيف تكتشف مصائد السيولة قبل حدوثها، ولماذا يستهدف صانع السوق القمم والقيعان المتساوية قبل الانطلاق في الاتجاه الحقيقي.', duration: '22:10', attachmentName: 'خريطة_السيولة_MZTRADER.pdf', sortOrder: 3 },
      { id: 'lesson-04', moduleId: m2, title: '4. تحديد مناطق الطلب والعرض المؤسسية (Order Blocks & FVG)', description: 'طريقة فلترة مناطق الـ Order Block عالية الاحتمال ودمجها مع الفجوات السعرية العادلة (Fair Value Gaps) للحصول على نقاط دخول ذات عائد إلى مخاطرة مرتفع.', duration: '25:30', attachmentName: 'فلترة_الاوردر_بلوك_MZTRADER.pdf', sortOrder: 4 },
      { id: 'lesson-05', moduleId: m3, title: '5. المعادلة الذهبية لحجم الصفقة وحماية رأس المال (Position Sizing)', description: 'كيفية حساب حجم العقد (Lot Size) بدقة بحيث لا تتجاوز المخاطرة 1% في الصفقة الواحدة مهما كان عدد نقاط وقف الخسارة.', duration: '16:15', attachmentName: 'جدول_إدارة_المخاطر_MZTRADER.pdf', sortOrder: 5 },
      { id: 'lesson-06', moduleId: m3, title: '6. بناء روتين المتداول اليومي وقائمة التحقق قبل الدخول (Pre-Trade Checklist)', description: 'الخطوات العملية قبل فتح أي صفقة: التوقيت الزمني للجلسات (لندن ونيويورك)، مراجعة الأخبار الاقتصادية، وتوثيق الصفقات.', duration: '19:50', attachmentName: 'قائمة_التحقق_اليومية_MZTRADER.pdf', sortOrder: 6 },
    ];

    for (const l of lessons) {
      const aesKeyHex = crypto.randomBytes(16).toString('hex');
      const aesIvHex = crypto.randomBytes(16).toString('hex');
      await execRun(
        `INSERT INTO videos (id, course_id, module_id, title, description, duration, video_url, aes_key_hex, aes_iv_hex, attachment_name, attachment_url, sort_order)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [l.id, courseId, l.moduleId, l.title, l.description, l.duration, sampleHls, aesKeyHex, aesIvHex, l.attachmentName, `/api/lessons/${l.id}/attachment`, l.sortOrder],
        conn
      );
    }

    return Number(courseId);
  });
}

async function syncAdminFromEnv(courseId) {
  const adminEmail = (process.env.ADMIN_EMAIL || '').trim().toLowerCase();
  const adminPassword = process.env.ADMIN_PASSWORD || '';
  const adminName = (process.env.ADMIN_NAME || 'MZTRADER Admin').trim();
  const adminPhone = (process.env.ADMIN_PHONE || '').trim();

  const existingAdmin = await queryOne("SELECT id, email, password_hash FROM users WHERE role = 'admin' ORDER BY id ASC LIMIT 1");

  if (!adminEmail || !adminPassword) {
    if (!existingAdmin) {
      console.warn('[MZTRADER] WARNING: Set ADMIN_EMAIL and ADMIN_PASSWORD environment variables to create the admin account.');
    }
    return;
  }

  if (!existingAdmin) {
    const adminHash = await argon2.hash(adminPassword);
    const watermarkCode = await uniqueWatermarkCode();
    await withTx(async (conn) => {
      const res = await execRun(
        `INSERT INTO users (full_name, email, phone, password_hash, role, watermark_code, requires_step_up, needs_review)
         VALUES (?, ?, ?, ?, 'admin', ?, 0, 0)`,
        [adminName, adminEmail, adminPhone, adminHash, watermarkCode],
        conn
      );
      await execRun(buildInsertIgnoreSql('enrollments (user_id, course_id, activated_via) VALUES (?, ?, ?)'), [res.lastInsertRowid, courseId, 'env-admin'], conn);
    });
    console.log(`[MZTRADER] Admin account initialized for ${adminEmail}`);
    return;
  }

  const emailChanged = existingAdmin.email !== adminEmail;
  let passwordChanged = false;
  try {
    passwordChanged = !(await argon2.verify(existingAdmin.password_hash, adminPassword));
  } catch {
    passwordChanged = true;
  }

  if (emailChanged || passwordChanged) {
    const newHash = passwordChanged ? await argon2.hash(adminPassword) : existingAdmin.password_hash;
    await execRun(
      `UPDATE users
          SET email = ?, password_hash = ?, full_name = ?, session_version = session_version + 1
        WHERE id = ?`,
      [adminEmail, newHash, adminName, existingAdmin.id]
    );
    console.log(`[MZTRADER] Admin credentials synced from environment for ${adminEmail}`);
  }
  await execRun(buildInsertIgnoreSql('enrollments (user_id, course_id, activated_via) VALUES (?, ?, ?)'), [existingAdmin.id, courseId, 'env-admin']);
}

async function initDb() {
  if (DB_ENGINE === 'postgres') {
    await initRemoteSchema(POSTGRES_SCHEMA_STATEMENTS, pgPool);
  } else if (DB_ENGINE === 'mysql') {
    await initRemoteSchema(MYSQL_SCHEMA_STATEMENTS, mysqlPool);
  } else {
    const schemaSql = fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8');
    sqlite.exec(schemaSql);
  }

  const courseId = await ensureCourseSeeded();
  await syncAdminFromEnv(courseId);
}

// ── Users ──────────────────────────────────────────────────────────
function mapUser(row) {
  if (!row) return null;
  return {
    ...row,
    id: Number(row.id),
    session_version: Number(row.session_version),
    active_stream_device_id: row.active_stream_device_id ? Number(row.active_stream_device_id) : null,
    requires_step_up: Boolean(row.requires_step_up),
    needs_review: Boolean(row.needs_review),
    is_banned: Boolean(row.is_banned),
    heartbeat_age_s: row.heartbeat_age_s !== null && row.heartbeat_age_s !== undefined ? Number(row.heartbeat_age_s) : null,
    country_age_min: row.country_age_min !== null && row.country_age_min !== undefined ? Number(row.country_age_min) : null,
  };
}

async function findUserByEmail(email) {
  const row = await queryOne('SELECT * FROM users WHERE email = ? LIMIT 1', [String(email).trim().toLowerCase()]);
  return mapUser(row);
}

const FIND_USER_SQL_BY_ENGINE = {
  postgres: `SELECT *,
                    FLOOR(EXTRACT(EPOCH FROM (NOW() - last_heartbeat_at)))::INTEGER AS heartbeat_age_s,
                    FLOOR(EXTRACT(EPOCH FROM (NOW() - last_country_at)) / 60)::INTEGER AS country_age_min
               FROM users WHERE id = ? LIMIT 1`,
  mysql: `SELECT *,
                 TIMESTAMPDIFF(SECOND, last_heartbeat_at, NOW()) AS heartbeat_age_s,
                 TIMESTAMPDIFF(MINUTE, last_country_at, NOW()) AS country_age_min
            FROM users WHERE id = ? LIMIT 1`,
  sqlite: `SELECT *,
                  CASE WHEN last_heartbeat_at IS NOT NULL
                       THEN CAST((julianday('now') - julianday(last_heartbeat_at)) * 86400 AS INTEGER)
                       ELSE NULL END AS heartbeat_age_s,
                  CASE WHEN last_country_at IS NOT NULL
                       THEN CAST((julianday('now') - julianday(last_country_at)) * 1440 AS INTEGER)
                       ELSE NULL END AS country_age_min
             FROM users WHERE id = ? LIMIT 1`,
};

async function findUserById(id) {
  const row = await queryOne(FIND_USER_SQL_BY_ENGINE[DB_ENGINE], [Number(id)]);
  return mapUser(row);
}

async function createUser({ fullName, email, phone, passwordHash, activationCode }) {
  return withTx(async (conn) => {
    const cleanEmail = String(email).trim().toLowerCase();
    const existing = await queryOne('SELECT id FROM users WHERE email = ? LIMIT 1', [cleanEmail], conn);
    if (existing) {
      const err = new Error('البريد الإلكتروني مسجل مسبقاً.');
      err.code = 'EMAIL_EXISTS';
      throw err;
    }

    const watermarkCode = await uniqueWatermarkCode(conn);
    const res = await execRun(
      `INSERT INTO users (full_name, email, phone, password_hash, role, watermark_code)
       VALUES (?, ?, ?, ?, 'student', ?)`,
      [String(fullName).trim(), cleanEmail, String(phone || '').trim(), passwordHash, watermarkCode],
      conn
    );
    const userId = res.lastInsertRowid;

    if (activationCode && String(activationCode).trim()) {
      const cleanCode = String(activationCode).trim().toUpperCase();
      const actRow = await queryOne('SELECT * FROM activation_codes WHERE code = ? AND used_by_user_id IS NULL LIMIT 1', [cleanCode], conn);
      if (!actRow) {
        const err = new Error('كود التفعيل غير صالح أو تم استخدامه مسبقاً.');
        err.code = 'INVALID_ACTIVATION_CODE';
        throw err;
      }
      await execRun(`UPDATE activation_codes SET used_by_user_id = ?, used_at = ${nowExpr} WHERE id = ?`, [userId, actRow.id], conn);
      const enrollSql = buildInsertIgnoreSql('enrollments (user_id, course_id, activated_via) VALUES (?, ?, ?)');
      await execRun(enrollSql, [userId, actRow.course_id, `code:${cleanCode}`], conn);
    }

    return mapUser(await queryOne('SELECT * FROM users WHERE id = ?', [userId], conn));
  });
}

async function setLastCountry(userId, country) {
  await execRun(`UPDATE users SET last_country = ?, last_country_at = ${nowExpr} WHERE id = ?`, [country, Number(userId)]);
}

// ── Devices ────────────────────────────────────────────────────────
async function findDevice(userId, jkt) {
  return queryOne('SELECT * FROM user_devices WHERE user_id = ? AND jwk_thumbprint = ? LIMIT 1', [Number(userId), String(jkt)]);
}

async function listDevices(userId) {
  return queryAll('SELECT id, device_label, last_ip, last_seen_at, created_at FROM user_devices WHERE user_id = ? ORDER BY last_seen_at DESC', [Number(userId)]);
}

async function touchDevice(deviceId, ip) {
  await execRun(
    `UPDATE user_devices SET last_ip = ?, last_seen_at = ${nowExpr}
      WHERE id = ? AND last_seen_at < ${minus5Min}`,
    [ip ?? null, Number(deviceId)]
  );
}

async function countRecentDeviceChanges(userId, conn = null) {
  const row = await queryOne(
    `SELECT COUNT(*) AS cnt FROM device_changes WHERE user_id = ? AND created_at > ${minus30Days}`,
    [Number(userId)],
    conn
  );
  return Number(row?.cnt ?? 0);
}

async function registerDeviceAtomic({ userId, jkt, publicKeyJwk, label, ip, replaceDeviceId, maxDevices, maxChangesPer30d }) {
  return withTx(async (conn) => {
    if (DB_ENGINE !== 'sqlite') {
      await queryOne('SELECT id FROM users WHERE id = ? FOR UPDATE', [Number(userId)], conn);
    }

    const existing = await queryOne('SELECT id FROM user_devices WHERE user_id = ? AND jwk_thumbprint = ? LIMIT 1', [Number(userId), String(jkt)], conn);
    if (existing) return { status: 'ok', replaced: false };

    const cntRow = await queryOne('SELECT COUNT(*) AS cnt FROM user_devices WHERE user_id = ?', [Number(userId)], conn);
    let replaced = false;

    if (Number(cntRow?.cnt ?? 0) >= maxDevices) {
      if (!replaceDeviceId) return { status: 'limit', replaced: false };
      if ((await countRecentDeviceChanges(userId, conn)) >= maxChangesPer30d) return { status: 'quota', replaced: false };

      const del = await execRun('DELETE FROM user_devices WHERE id = ? AND user_id = ?', [Number(replaceDeviceId), Number(userId)], conn);
      if (del.changes !== 1) return { status: 'limit', replaced: false };
      await execRun('INSERT INTO device_changes (user_id) VALUES (?)', [Number(userId)], conn);
      replaced = true;
    }

    await execRun(
      `INSERT INTO user_devices (user_id, device_label, jwk_thumbprint, public_key_jwk, last_ip)
       VALUES (?, ?, ?, ?, ?)`,
      [Number(userId), label, String(jkt), publicKeyJwk, ip ?? null],
      conn
    );
    return { status: 'ok', replaced };
  });
}

async function removeDeviceWithQuota(userId, deviceId, maxChangesPer30d) {
  return withTx(async (conn) => {
    if (DB_ENGINE !== 'sqlite') {
      await queryOne('SELECT id FROM users WHERE id = ? FOR UPDATE', [Number(userId)], conn);
    }
    if ((await countRecentDeviceChanges(userId, conn)) >= maxChangesPer30d) return 'quota';

    const del = await execRun('DELETE FROM user_devices WHERE id = ? AND user_id = ?', [Number(deviceId), Number(userId)], conn);
    if (del.changes !== 1) return 'not_found';

    await execRun('INSERT INTO device_changes (user_id) VALUES (?)', [Number(userId)], conn);
    return 'ok';
  });
}

// ── DPoP Replay Cache ──────────────────────────────────────────────
async function consumeDpopJti(jti, expiresAtEpochSec) {
  try {
    await execRun('INSERT INTO dpop_jti_cache (jti, expires_at) VALUES (?, ?)', [String(jti), Number(expiresAtEpochSec)]);
    return true;
  } catch (err) {
    if (
      err.code === 'ER_DUP_ENTRY' ||
      err.code === '23505' ||
      String(err.message).includes('UNIQUE') ||
      String(err.message).includes('Duplicate') ||
      String(err.message).includes('duplicate key')
    ) {
      return false;
    }
    throw err;
  }
}

// ── Email Codes ────────────────────────────────────────────────────
async function createEmailCode(userId, purpose, jkt) {
  const code = crypto.randomInt(0, 1_000_000).toString().padStart(6, '0');
  await execRun(
    `UPDATE email_codes SET consumed_at = ${nowExpr} WHERE user_id = ? AND purpose = ? AND consumed_at IS NULL`,
    [Number(userId), String(purpose)]
  );
  await execRun(
    `INSERT INTO email_codes (user_id, purpose, jwk_thumbprint, code_hash, raw_code_preview, expires_at)
     VALUES (?, ?, ?, ?, ?, ${plus10Min})`,
    [Number(userId), String(purpose), String(jkt), hashCode(code), code]
  );
  return code;
}

async function verifyEmailCode(userId, purpose, jkt, code) {
  if (!/^\d{6}$/.test(String(code))) return false;
  const row = await queryOne(
    `SELECT id, code_hash, attempts FROM email_codes
      WHERE user_id = ? AND purpose = ? AND jwk_thumbprint = ?
        AND consumed_at IS NULL AND expires_at > ${nowExpr}
      ORDER BY id DESC LIMIT 1`,
    [Number(userId), String(purpose), String(jkt)]
  );
  if (!row || Number(row.attempts) >= 5) return false;

  const match = crypto.timingSafeEqual(Buffer.from(row.code_hash, 'hex'), Buffer.from(hashCode(code), 'hex'));
  if (!match) {
    await execRun('UPDATE email_codes SET attempts = attempts + 1 WHERE id = ?', [row.id]);
    return false;
  }
  const res = await execRun(`UPDATE email_codes SET consumed_at = ${nowExpr} WHERE id = ? AND consumed_at IS NULL`, [row.id]);
  return res.changes === 1;
}

// ── Entitlements, Activation & Streams ─────────────────────────────
async function isUserEnrolled(userId) {
  const row = await queryOne(
    `SELECT 1 FROM enrollments WHERE user_id = ? AND (expires_at IS NULL OR expires_at > ${nowExpr}) LIMIT 1`,
    [Number(userId)]
  );
  return Boolean(row);
}

async function hasEntitlement(userId, videoId) {
  const row = await queryOne(
    `SELECT 1 FROM videos v
       JOIN enrollments e ON e.course_id = v.course_id
      WHERE v.id = ? AND e.user_id = ? AND (e.expires_at IS NULL OR e.expires_at > ${nowExpr})
      LIMIT 1`,
    [String(videoId), Number(userId)]
  );
  return Boolean(row);
}

async function getVideoById(videoId) {
  return queryOne('SELECT * FROM videos WHERE id = ? LIMIT 1', [String(videoId)]);
}

async function redeemActivationCode(userId, rawCode) {
  const cleanCode = String(rawCode || '').trim().toUpperCase();
  if (!cleanCode) return { ok: false, error: 'يرجى إدخال كود التفعيل.' };

  return withTx(async (conn) => {
    const actRow = await queryOne('SELECT * FROM activation_codes WHERE code = ? AND used_by_user_id IS NULL LIMIT 1', [cleanCode], conn);
    if (!actRow) return { ok: false, error: 'كود التفعيل غير صالح أو تم استخدامه مسبقاً.' };

    await execRun(`UPDATE activation_codes SET used_by_user_id = ?, used_at = ${nowExpr} WHERE id = ?`, [Number(userId), actRow.id], conn);
    const enrollSql = buildInsertIgnoreSql('enrollments (user_id, course_id, activated_via) VALUES (?, ?, ?)');
    await execRun(enrollSql, [Number(userId), actRow.course_id, `code:${cleanCode}`], conn);
    return { ok: true };
  });
}

async function claimStream(userId, deviceId, streamId) {
  await execRun(
    `UPDATE users SET active_stream_id = ?, active_stream_device_id = ?, last_heartbeat_at = ${nowExpr} WHERE id = ?`,
    [String(streamId), Number(deviceId), Number(userId)]
  );
}

async function heartbeat(userId, streamId) {
  const res = await execRun(
    `UPDATE users SET last_heartbeat_at = ${nowExpr} WHERE id = ? AND active_stream_id = ?`,
    [Number(userId), String(streamId)]
  );
  return res.changes === 1;
}

async function releaseStream(userId, deviceId) {
  await execRun(
    'UPDATE users SET active_stream_id = NULL WHERE id = ? AND active_stream_device_id = ?',
    [Number(userId), Number(deviceId)]
  );
}

// ── Course Curriculum & Progress ───────────────────────────────────
async function getCourseCurriculumForUser(userId) {
  const course = await queryOne('SELECT * FROM courses ORDER BY id ASC LIMIT 1');
  if (!course) return null;
  const modules = await queryAll('SELECT * FROM modules WHERE course_id = ? ORDER BY sort_order ASC, id ASC', [course.id]);
  const videos = await queryAll(
    'SELECT id, course_id, module_id, title, description, duration, attachment_name, attachment_url, sort_order FROM videos WHERE course_id = ? ORDER BY sort_order ASC, id ASC',
    [course.id]
  );
  const completedRows = await queryAll('SELECT video_id FROM lesson_progress WHERE user_id = ?', [Number(userId)]);
  const completedSet = new Set(completedRows.map((r) => r.video_id));

  return {
    id: course.id,
    title: course.title,
    description: course.description,
    totalLessons: videos.length,
    completedCount: completedSet.size,
    modules: modules.map((m) => ({
      id: m.id,
      title: m.title,
      sortOrder: m.sort_order,
      lessons: videos
        .filter((v) => Number(v.module_id) === Number(m.id))
        .map((v) => ({
          ...v,
          completed: completedSet.has(v.id),
        })),
    })),
  };
}

async function toggleLessonComplete(userId, videoId, completed = true) {
  if (completed) {
    await execRun(buildInsertIgnoreSql('lesson_progress (user_id, video_id) VALUES (?, ?)'), [Number(userId), String(videoId)]);
  } else {
    await execRun('DELETE FROM lesson_progress WHERE user_id = ? AND video_id = ?', [Number(userId), String(videoId)]);
  }
}

// ── Risk ───────────────────────────────────────────────────────────
async function insertEvent(userId, type, points, ip, meta = {}) {
  await execRun(
    'INSERT INTO security_events (user_id, type, points, ip, meta) VALUES (?, ?, ?, ?, ?)',
    [Number(userId), String(type), Number(points), ip ?? null, JSON.stringify(meta)]
  );
}

async function currentRiskScore(userId) {
  const row = await queryOne(
    `SELECT COALESCE(SUM(points), 0) AS score
       FROM security_events
      WHERE user_id = ?
        AND created_at > ${minus7Days}
        AND id > COALESCE((SELECT max_id FROM (SELECT MAX(id) AS max_id FROM security_events WHERE user_id = ? AND type = 'step_up_passed') AS t), 0)`,
    [Number(userId), Number(userId)]
  );
  return Number(row?.score ?? 0);
}

async function raiseRiskFlags(userId, { stepUp, review }) {
  await execRun(
    `UPDATE users
        SET requires_step_up = CASE WHEN requires_step_up = 1 THEN 1 ELSE ? END,
            needs_review     = CASE WHEN needs_review = 1 THEN 1 ELSE ? END
      WHERE id = ?`,
    [stepUp ? 1 : 0, review ? 1 : 0, Number(userId)]
  );
}

async function clearStepUp(userId) {
  await execRun('UPDATE users SET requires_step_up = 0 WHERE id = ?', [Number(userId)]);
}

// ── Admin Queries ──────────────────────────────────────────────────
async function getAdminOverview() {
  const users = await queryAll(`
    SELECT u.id, u.full_name, u.email, u.phone, u.role, u.watermark_code,
           u.requires_step_up, u.needs_review, u.is_banned, u.ban_reason,
           u.last_country, u.last_heartbeat_at, u.created_at,
           (SELECT COUNT(*) FROM user_devices d WHERE d.user_id = u.id) AS device_count,
           (SELECT COUNT(*) FROM enrollments e WHERE e.user_id = u.id) AS enroll_count
      FROM users u
     ORDER BY u.id DESC
  `);

  const enrichedUsers = [];
  for (const u of users) {
    const riskScore = await currentRiskScore(u.id);
    const events = await queryAll('SELECT id, type, points, ip, meta, created_at FROM security_events WHERE user_id = ? ORDER BY id DESC LIMIT 15', [u.id]);
    const devices = await queryAll('SELECT id, device_label, last_ip, last_seen_at, created_at FROM user_devices WHERE user_id = ? ORDER BY last_seen_at DESC', [u.id]);
    enrichedUsers.push({
      ...mapUser(u),
      is_enrolled: Number(u.enroll_count) > 0,
      device_count: Number(u.device_count),
      risk_score: riskScore,
      events,
      devices,
    });
  }

  const activationCodes = await queryAll(`
    SELECT a.*, u.email AS used_by_email, u.full_name AS used_by_name
      FROM activation_codes a
      LEFT JOIN users u ON u.id = a.used_by_user_id
     ORDER BY a.id DESC
  `);

  const otpLogs = await queryAll(`
    SELECT c.id, c.purpose, c.raw_code_preview, c.attempts, c.expires_at, c.consumed_at, c.created_at,
           u.email, u.full_name, u.watermark_code
      FROM email_codes c
      JOIN users u ON u.id = c.user_id
     ORDER BY c.id DESC LIMIT 30
  `);

  const course = await queryOne('SELECT * FROM courses ORDER BY id ASC LIMIT 1');
  const modules = course ? await queryAll('SELECT * FROM modules WHERE course_id = ? ORDER BY sort_order ASC, id ASC', [course.id]) : [];
  const videos = course ? await queryAll('SELECT * FROM videos WHERE course_id = ? ORDER BY sort_order ASC, id ASC', [course.id]) : [];

  return {
    users: enrichedUsers,
    activationCodes,
    otpLogs,
    course: course ? { ...course, modules, videos } : null,
  };
}

async function adminToggleEnroll(userId, enroll) {
  const course = await queryOne('SELECT id FROM courses ORDER BY id ASC LIMIT 1');
  if (!course) return;
  if (enroll) {
    await execRun(buildInsertIgnoreSql("enrollments (user_id, course_id, activated_via) VALUES (?, ?, 'admin')"), [Number(userId), course.id]);
  } else {
    await execRun('DELETE FROM enrollments WHERE user_id = ?', [Number(userId)]);
  }
}

async function adminGenerateCodes(count = 5) {
  const course = await queryOne('SELECT id FROM courses ORDER BY id ASC LIMIT 1');
  if (!course) return [];
  const n = Math.min(50, Math.max(1, Number(count) || 1));
  const created = [];
  for (let i = 0; i < n; i++) {
    const rand = crypto.randomBytes(3).toString('hex').toUpperCase();
    const code = `MZT-VIP-${rand}`;
    await execRun('INSERT INTO activation_codes (code, course_id) VALUES (?, ?)', [code, course.id]);
    created.push(code);
  }
  return created;
}

async function adminCreateModule(title) {
  const course = await queryOne('SELECT id FROM courses ORDER BY id ASC LIMIT 1');
  const maxRow = await queryOne('SELECT COALESCE(MAX(sort_order), 0) AS m FROM modules WHERE course_id = ?', [course.id]);
  const res = await execRun(
    'INSERT INTO modules (course_id, title, sort_order) VALUES (?, ?, ?)',
    [course.id, String(title).trim(), Number(maxRow?.m ?? 0) + 1]
  );
  return res.lastInsertRowid;
}

async function adminSaveVideo({ id, moduleId, title, description, duration, videoUrl, aesKeyHex, attachmentName }) {
  const course = await queryOne('SELECT id FROM courses ORDER BY id ASC LIMIT 1');
  const slug = id && /^[a-zA-Z0-9_-]{1,64}$/.test(id) ? id : `lesson-${Date.now().toString(36)}`;
  const keyHex = aesKeyHex && /^[0-9a-fA-F]{32}$/.test(aesKeyHex) ? aesKeyHex.toLowerCase() : crypto.randomBytes(16).toString('hex');
  const ivHex = crypto.randomBytes(16).toString('hex');
  const maxRow = await queryOne('SELECT COALESCE(MAX(sort_order), 0) AS m FROM videos WHERE course_id = ?', [course.id]);

  const existing = await queryOne('SELECT id FROM videos WHERE id = ?', [slug]);
  if (existing) {
    await execRun(
      `UPDATE videos
          SET module_id = ?, title = ?, description = ?, duration = ?, video_url = ?, aes_key_hex = ?, attachment_name = ?
        WHERE id = ?`,
      [Number(moduleId), String(title).trim(), String(description || '').trim(), String(duration || '15:00').trim(), String(videoUrl).trim(), keyHex, attachmentName || null, slug]
    );
  } else {
    await execRun(
      `INSERT INTO videos (id, course_id, module_id, title, description, duration, video_url, aes_key_hex, aes_iv_hex, attachment_name, attachment_url, sort_order)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [slug, course.id, Number(moduleId), String(title).trim(), String(description || '').trim(), String(duration || '15:00').trim(), String(videoUrl).trim(), keyHex, ivHex, attachmentName || 'ملف_مرفق_MZTRADER.pdf', `/api/lessons/${slug}/attachment`, Number(maxRow?.m ?? 0) + 1]
    );
  }
  return slug;
}

async function adminLookupByWatermark(query) {
  const clean = String(query || '').trim().toUpperCase().replace(/^MZTRADER\s*•?\s*ID:\s*/i, '').replace(/^ID:\s*/i, '');
  const user = await queryOne(
    `SELECT * FROM users
      WHERE UPPER(watermark_code) = ? OR UPPER(watermark_code) LIKE ? OR UPPER(email) = ?
      LIMIT 1`,
    [clean, `%${clean}%`, clean]
  );
  if (!user) return null;

  const devices = await listDevices(user.id);
  const events = await queryAll('SELECT * FROM security_events WHERE user_id = ? ORDER BY id DESC LIMIT 25', [user.id]);
  const riskScore = await currentRiskScore(user.id);
  return {
    user: mapUser(user),
    riskScore,
    devices,
    events,
  };
}

async function adminClearRisk(userId) {
  await insertEvent(userId, 'step_up_passed', 0, 'admin', { clearedBy: 'admin' });
  await execRun('UPDATE users SET requires_step_up = 0, needs_review = 0 WHERE id = ?', [Number(userId)]);
}

async function adminResetDeviceQuota(userId) {
  await execRun('DELETE FROM device_changes WHERE user_id = ?', [Number(userId)]);
}

async function adminForceLogoutEverywhere(userId) {
  await execRun('UPDATE users SET session_version = session_version + 1, active_stream_id = NULL WHERE id = ?', [Number(userId)]);
}

async function adminSetBan(userId, isBanned, reason = '') {
  await execRun(
    `UPDATE users
        SET is_banned = ?, ban_reason = ?, session_version = session_version + 1, active_stream_id = NULL
      WHERE id = ?`,
    [isBanned ? 1 : 0, isBanned ? String(reason || 'مخالفة شروط الاستخدام وتسريب المحتوى') : null, Number(userId)]
  );
}

// ── Lazy Housekeeping (Allows Layerbase DB to Sleep on Idle) ───────
let lastPrunedAt = 0;
async function pruneExpired() {
  const now = Date.now();
  if (now - lastPrunedAt < 15 * 60 * 1000) return;
  lastPrunedAt = now;
  const nowSec = Math.floor(now / 1000);
  await execRun('DELETE FROM dpop_jti_cache WHERE expires_at < ?', [nowSec]);
  await execRun(`DELETE FROM email_codes WHERE expires_at < ${minus1Day}`);
  await execRun(`DELETE FROM security_events WHERE created_at < ${minus90Days}`);
}

module.exports = {
  USE_MYSQL,
  DB_ENGINE,
  DB_LABEL,
  toPgSql,
  initDb,
  findUserByEmail,
  findUserById,
  createUser,
  setLastCountry,
  findDevice,
  listDevices,
  touchDevice,
  countRecentDeviceChanges,
  registerDeviceAtomic,
  removeDeviceWithQuota,
  consumeDpopJti,
  createEmailCode,
  verifyEmailCode,
  isUserEnrolled,
  hasEntitlement,
  getVideoById,
  redeemActivationCode,
  claimStream,
  heartbeat,
  releaseStream,
  getCourseCurriculumForUser,
  toggleLessonComplete,
  insertEvent,
  currentRiskScore,
  raiseRiskFlags,
  clearStepUp,
  getAdminOverview,
  adminToggleEnroll,
  adminGenerateCodes,
  adminCreateModule,
  adminSaveVideo,
  adminLookupByWatermark,
  adminClearRisk,
  adminResetDeviceQuota,
  adminForceLogoutEverywhere,
  adminSetBan,
  pruneExpired,
};
