-- MZTRADER Database Schema (SQLite / MySQL 8 Compatible)
-- Brand: MZTRADER

CREATE TABLE IF NOT EXISTS users (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name                TEXT NOT NULL,
    email                   TEXT NOT NULL UNIQUE,          -- stored lowercase
    phone                   TEXT NOT NULL DEFAULT '',
    password_hash           TEXT NOT NULL,                 -- argon2id
    role                    TEXT NOT NULL DEFAULT 'student', -- 'student' | 'admin'
    watermark_code          TEXT NOT NULL UNIQUE,          -- e.g. "MZT-4091-A"
    session_version         INTEGER NOT NULL DEFAULT 1,    -- bump = log out everywhere

    -- Single active stream lease (newest stream wins)
    active_stream_id        TEXT NULL,
    active_stream_device_id INTEGER NULL,
    last_heartbeat_at       TEXT NULL,

    -- Country-level location signal
    last_country            TEXT NULL,
    last_country_at         TEXT NULL,

    -- Risk state (never auto-ban)
    requires_step_up        INTEGER NOT NULL DEFAULT 0,
    needs_review            INTEGER NOT NULL DEFAULT 0,
    is_banned               INTEGER NOT NULL DEFAULT 0,
    ban_reason              TEXT NULL,
    created_at              TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS user_devices (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL,
    device_label    TEXT NOT NULL,
    jwk_thumbprint  TEXT NOT NULL,   -- RFC 7638 SHA-256 base64url (43 chars)
    public_key_jwk  TEXT NOT NULL,   -- canonical public P-256 JWK only
    last_ip         TEXT NULL,
    last_seen_at    TEXT NOT NULL DEFAULT (datetime('now')),
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (user_id, jwk_thumbprint),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS device_changes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS email_codes (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id           INTEGER NOT NULL,
    purpose           TEXT NOT NULL, -- 'new_device' | 'step_up'
    jwk_thumbprint    TEXT NOT NULL,
    code_hash         TEXT NOT NULL, -- HMAC-SHA256 hex
    raw_code_preview  TEXT NULL,     -- Shown in Admin Live OTP Log for $0 testing / WhatsApp support
    attempts          INTEGER NOT NULL DEFAULT 0,
    expires_at        TEXT NOT NULL,
    consumed_at       TEXT NULL,
    created_at        TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS security_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL,
    type        TEXT NOT NULL,
    points      INTEGER NOT NULL DEFAULT 0,
    ip          TEXT NULL,
    meta        TEXT NULL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS dpop_jti_cache (
    jti         TEXT PRIMARY KEY,
    expires_at  INTEGER NOT NULL -- Unix epoch seconds
);

CREATE TABLE IF NOT EXISTS courses (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    title       TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS modules (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    course_id   INTEGER NOT NULL,
    title       TEXT NOT NULL,
    sort_order  INTEGER NOT NULL DEFAULT 1,
    FOREIGN KEY (course_id) REFERENCES courses(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS videos (
    id              TEXT PRIMARY KEY,              -- Slug e.g. "lesson-01"
    course_id       INTEGER NOT NULL,
    module_id       INTEGER NOT NULL,
    title           TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    duration        TEXT NOT NULL DEFAULT '12:00',
    video_url       TEXT NOT NULL,                 -- External HLS .m3u8 URL or CDN base URL
    aes_key_hex     TEXT NOT NULL,                 -- 16-byte AES-128 key (32 hex chars) stored in DB
    aes_iv_hex      TEXT NOT NULL,                 -- 16-byte AES-128 IV (32 hex chars)
    attachment_name TEXT NULL,
    attachment_url  TEXT NULL,
    sort_order      INTEGER NOT NULL DEFAULT 1,
    FOREIGN KEY (course_id) REFERENCES courses(id) ON DELETE CASCADE,
    FOREIGN KEY (module_id) REFERENCES modules(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS lesson_progress (
    user_id       INTEGER NOT NULL,
    video_id      TEXT NOT NULL,
    completed_at  TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (user_id, video_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (video_id) REFERENCES videos(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS enrollments (
    user_id        INTEGER NOT NULL,
    course_id      INTEGER NOT NULL,
    activated_via  TEXT NOT NULL DEFAULT 'admin',
    expires_at     TEXT NULL, -- NULL = lifetime access
    created_at     TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (user_id, course_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (course_id) REFERENCES courses(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS activation_codes (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    code             TEXT NOT NULL UNIQUE,
    course_id        INTEGER NOT NULL DEFAULT 1,
    used_by_user_id  INTEGER NULL,
    used_at          TEXT NULL,
    created_at       TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (course_id) REFERENCES courses(id) ON DELETE CASCADE,
    FOREIGN KEY (used_by_user_id) REFERENCES users(id) ON DELETE SET NULL
);
