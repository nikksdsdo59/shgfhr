const express = require('express');
const crypto  = require('crypto');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const path    = require('path');
const db      = require('./db');

const app = express();
const SECRET = process.env.JWT_SECRET || 'change-moi-en-prod-xyz';

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const now = () => Date.now();

function genKey(n = 20) {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let s = '';
  for (let i = 0; i < n; i++) s += chars[crypto.randomInt(chars.length)];
  return s;
}
function signUser(u) {
  return jwt.sign({ id: u.id, username: u.username, type: 'user' }, SECRET, { expiresIn: '24h' });
}
function pub(u) {
  const k = db.prepare('SELECT key, duration_days, expires_at FROM keys WHERE id=?').get(u.key_id) || {};
  return { id: u.id, username: u.username, key: k.key || null, expires_at: k.expires_at || null, hwid: u.hwid };
}
function adminOnly(req, res, next) {
  try {
    const t = req.headers['x-admin-token'];
    req.admin = jwt.verify(t, SECRET);
    if (req.admin.type !== 'admin') throw 0;
    next();
  } catch { res.status(401).json({ ok: false, error: 'Non autorise' }); }
}

/* ============ AUTH (utilise par le cheat) ============ */
app.post('/api/auth/login', (req, res) => {
  const { username, password, key, hwid } = req.body || {};
  if (!username || !password || !hwid)
    return res.json({ ok: false, error: 'Champs manquants' });

  let user = db.prepare('SELECT * FROM users WHERE username=?').get(username);

  /* --- Compte existant --- */
  if (user) {
    if (!bcrypt.compareSync(password, user.password))
      return res.json({ ok: false, error: 'Mot de passe incorrect' });
    if (user.banned)
      return res.json({ ok: false, error: 'Compte banni' });
    if (user.hwid && user.hwid !== hwid)
      return res.json({ ok: false, error: 'HWID different (reset via admin)' });

    const k = db.prepare('SELECT * FROM keys WHERE id=?').get(user.key_id);
    if (k && k.expires_at && now() > k.expires_at)
      return res.json({ ok: false, error: 'Cle expiree' });

    db.prepare('UPDATE users SET last_login=? WHERE id=?').run(now(), user.id);
    db.prepare('INSERT INTO logs (user_id,action,hwid,ip,ts) VALUES (?,?,?,?,?)')
      .run(user.id, 'login', hwid, req.ip, now());

    return res.json({ ok: true, token: signUser(user), user: pub(user) });
  }

  /* --- Nouveau compte : la CLE est OBLIGATOIRE --- */
  if (!key) return res.json({ ok: false, error: 'Cle requise pour creer un compte' });

  const krow = db.prepare('SELECT * FROM keys WHERE key=?').get(String(key).trim().toUpperCase());
  if (!krow)        return res.json({ ok: false, error: 'Cle invalide' });
  if (krow.used_by) return res.json({ ok: false, error: 'Cle deja utilisee' });
  if (krow.expires_at && now() > krow.expires_at)
    return res.json({ ok: false, error: 'Cle expiree' });

  const hash = bcrypt.hashSync(password, 10);
  const info = db.prepare(
    'INSERT INTO users (username,password,key_id,hwid,created_at,last_login) VALUES (?,?,?,?,?,?)'
  ).run(username, hash, krow.id, hwid, now(), now());

  db.prepare('UPDATE keys SET used_by=? WHERE id=?').run(info.lastInsertRowid, krow.id);
  db.prepare('INSERT INTO logs (user_id,action,hwid,ip,ts) VALUES (?,?,?,?,?)')
    .run(info.lastInsertRowid, 'register', hwid, req.ip, now());

  const u2 = db.prepare('SELECT * FROM users WHERE id=?').get(info.lastInsertRowid);
  res.json({ ok: true, token: signUser(u2), user: pub(u2) });
});

app.post('/api/auth/heartbeat', (req, res) => {
  try { jwt.verify(req.body.token, SECRET); res.json({ ok: true }); }
  catch { res.json({ ok: false }); }
});

/* ============ ADMIN ============ */
app.post('/api/admin/login', (req, res) => {
  const { username, password } = req.body || {};
  const a = db.prepare('SELECT * FROM admins WHERE username=?').get(username);
  if (!a || !bcrypt.compareSync(password, a.password))
    return res.json({ ok: false, error: 'Identifiants invalides' });
  res.json({ ok: true, token: jwt.sign({ id: a.id, username: a.username, type: 'admin' }, SECRET, { expiresIn: '12h' }) });
});

app.post('/api/admin/keys', adminOnly, (req, res) => {
  const count = Math.min(Number(req.body.count) || 1, 1000);
  const days  = Number(req.body.duration_days ?? 30);
  const note  = String(req.body.note || '');
  const out = [];
  const ins = db.prepare('INSERT INTO keys (key,duration_days,created_at,expires_at,note) VALUES (?,?,?,?,?)');
  const exists = db.prepare('SELECT 1 FROM keys WHERE key=?');
  for (let i = 0; i < count; i++) {
    let k;
    do { k = genKey(); } while (exists.get(k));
    ins.run(k, days, now(), days > 0 ? now() + days * 86400000 : null, note);
    out.push(k);
  }
  res.json({ ok: true, keys: out });
});

app.get('/api/admin/keys', adminOnly, (req, res) => {
  res.json({ ok: true, keys: db.prepare(`
    SELECT k.*, u.username AS used_by_name
    FROM keys k LEFT JOIN users u ON u.id = k.used_by
    ORDER BY k.id DESC`).all() });
});

app.delete('/api/admin/keys/:id', adminOnly, (req, res) => {
  db.prepare('DELETE FROM keys WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});

app.get('/api/admin/users', adminOnly, (req, res) => {
  res.json({ ok: true, users: db.prepare(`
    SELECT u.id,u.username,u.hwid,u.banned,u.created_at,u.last_login,k.key,k.expires_at
    FROM users u LEFT JOIN keys k ON k.id=u.key_id
    ORDER BY u.id DESC`).all() });
});

app.post('/api/admin/users/:id/ban', adminOnly, (req, res) => {
  db.prepare('UPDATE users SET banned=? WHERE id=?').run(req.body.banned ? 1 : 0, req.params.id);
  res.json({ ok: true });
});

app.post('/api/admin/users/:id/reset-hwid', adminOnly, (req, res) => {
  db.prepare('UPDATE users SET hwid=NULL WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});

app.delete('/api/admin/users/:id', adminOnly, (req, res) => {
  db.prepare('DELETE FROM users WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`[PANEL] http://localhost:${PORT}`));
