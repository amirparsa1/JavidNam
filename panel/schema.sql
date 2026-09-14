-- JavidNam Panel — D1 schema (original, GPL-3.0)
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  uuid TEXT UNIQUE NOT NULL,
  trojan_hash TEXT,
  name TEXT,
  sub_token TEXT UNIQUE NOT NULL,
  quota_bytes INTEGER DEFAULT 0,
  used_bytes INTEGER DEFAULT 0,
  reset_hours INTEGER DEFAULT 0,
  last_reset_at INTEGER,
  days INTEGER DEFAULT 0,
  expiry_at INTEGER,
  start_on_first INTEGER DEFAULT 0,
  first_connect_at INTEGER,
  ip_limit INTEGER DEFAULT 0,
  active INTEGER DEFAULT 1,
  note TEXT,
  created_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_users_uuid ON users(uuid);
CREATE INDEX IF NOT EXISTS idx_users_trojan ON users(trojan_hash);
CREATE INDEX IF NOT EXISTS idx_users_token ON users(sub_token);

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT
);

CREATE TABLE IF NOT EXISTS login_attempts (
  ip TEXT PRIMARY KEY,
  fails INTEGER DEFAULT 0,
  banned_until INTEGER
);
