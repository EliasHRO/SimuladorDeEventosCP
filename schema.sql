-- Base de datos del Simulador de escenario (Cloudflare D1)
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  pass_hash TEXT NOT NULL,
  pass_salt TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user',        -- 'owner' o 'user'
  status TEXT NOT NULL DEFAULT 'pending',   -- 'pending', 'active' o 'blocked'
  perms TEXT,                               -- permisos en JSON
  message TEXT,
  must_change INTEGER NOT NULL DEFAULT 0,   -- 1 = debe cambiar la contraseña temporal
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE TABLE IF NOT EXISTS config (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS login_attempts (
  email TEXT NOT NULL,
  at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_attempts ON login_attempts(email, at);
