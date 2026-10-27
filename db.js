const Database = require('better-sqlite3');
const bcrypt   = require('bcryptjs');

const db = new Database('panel.db');
db.pragma('journal_mode = WAL');

db.exec(`
CREATE TABLE IF NOT EXISTS admins (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key TEXT UNIQUE NOT NULL,
  duration_days INTEGER DEFAULT 30,
  used_by INTEGER DEFAULT NULL,
  note TEXT DEFAULT '',
  created_at INTEGER,
  expires_at INTEGER
);
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  key_id INTEGER,
  hwid TEXT,
  banned INTEGER DEFAULT 0,
  created_at INTEGER,
  last_login INTEGER
);
CREATE TABLE IF NOT EXISTS logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  action TEXT,
  hwid TEXT,
  ip TEXT,
  ts INTEGER
);
`);

// Compte admin par defaut : admin / admin  (change-le vite !)
if (db.prepare('SELECT COUNT(*) c FROM admins').get().c === 0) {
  db.prepare('INSERT INTO admins (username,password) VALUES (?,?)')
    .run('admin', bcrypt.hashSync('admin', 10));
  console.log('[DB] Admin par defaut cree -> admin / admin');
}

module.exports = db;
