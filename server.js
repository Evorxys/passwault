'use strict';

const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');

if (!process.env.JWT_SECRET) {
  console.warn('⚠  JWT_SECRET not set — using random secret (sessions will reset on restart)');
}

// ── Database ────────────────────────────────────────────────────────────────
const pool = new Pool({
  host:     process.env.PGHOST,
  database: process.env.PGDATABASE,
  user:     process.env.PGUSER,
  password: process.env.PGPASSWORD,
  ssl:      { rejectUnauthorized: true },
  max: 10,
});

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id            SERIAL PRIMARY KEY,
      username      TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at    TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS vault_entries (
      id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      site         TEXT NOT NULL,
      username_enc TEXT,
      username_iv  TEXT,
      password_enc TEXT NOT NULL,
      iv           TEXT NOT NULL,
      notes_enc    TEXT,
      notes_iv     TEXT,
      labels       TEXT[]   NOT NULL DEFAULT '{}',
      color        TEXT     NOT NULL DEFAULT 'default',
      pinned       BOOLEAN  NOT NULL DEFAULT FALSE,
      folder       TEXT     NOT NULL DEFAULT '',
      updated_at   TIMESTAMPTZ DEFAULT NOW(),
      created_at   TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS devices (
      id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      name       TEXT NOT NULL,
      last_seen  TIMESTAMPTZ DEFAULT NOW(),
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  // Safe migration for databases created before these columns existed
  await pool.query(`
    ALTER TABLE vault_entries ADD COLUMN IF NOT EXISTS labels  TEXT[]  NOT NULL DEFAULT '{}';
    ALTER TABLE vault_entries ADD COLUMN IF NOT EXISTS color   TEXT    NOT NULL DEFAULT 'default';
    ALTER TABLE vault_entries ADD COLUMN IF NOT EXISTS pinned  BOOLEAN NOT NULL DEFAULT FALSE;
    ALTER TABLE vault_entries ADD COLUMN IF NOT EXISTS folder  TEXT    NOT NULL DEFAULT '';
  `);

  // Migrate legacy single-category field to labels array (if old column exists)
  const hasCat = await pool.query(`
    SELECT 1 FROM information_schema.columns
    WHERE table_name='vault_entries' AND column_name='category'
  `);
  if (hasCat.rows.length) {
    await pool.query(`
      UPDATE vault_entries
      SET labels = ARRAY[category]
      WHERE category IS NOT NULL AND category <> '' AND labels = '{}';
    `);
  }

  console.log('✅ Database ready');
}

// ── Middleware ──────────────────────────────────────────────────────────────
app.use(express.json({ limit: '4mb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

function auth(req, res, next) {
  const token = req.cookies?.token || req.headers?.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Not authenticated' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Session expired' });
  }
}

// ── Auth routes ─────────────────────────────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
  const { username, password, deviceName } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  if (username.length < 3) return res.status(400).json({ error: 'Username must be at least 3 characters' });
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });

  try {
    const exists = await pool.query('SELECT id FROM users WHERE username=$1', [username.toLowerCase()]);
    if (exists.rows.length) return res.status(409).json({ error: 'Username already taken' });

    const hash = await bcrypt.hash(password, 12);
    const result = await pool.query(
      'INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id',
      [username.toLowerCase(), hash]
    );
    const userId = result.rows[0].id;

    if (deviceName) {
      await pool.query('INSERT INTO devices (user_id, name) VALUES ($1, $2)', [userId, deviceName]);
    }

    const token = jwt.sign({ userId, username: username.toLowerCase() }, JWT_SECRET, { expiresIn: '30d' });
    res.cookie('token', token, { httpOnly: true, secure: true, sameSite: 'strict', maxAge: 30*24*60*60*1000 });
    res.json({ ok: true, username: username.toLowerCase() });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { username, password, deviceName } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

  try {
    const result = await pool.query('SELECT id, password_hash FROM users WHERE username=$1', [username.toLowerCase()]);
    if (!result.rows.length) return res.status(401).json({ error: 'Invalid username or password' });

    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid username or password' });

    if (deviceName) {
      await pool.query(
        `INSERT INTO devices (user_id, name) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
        [user.id, deviceName]
      );
      await pool.query('UPDATE devices SET last_seen=NOW() WHERE user_id=$1 AND name=$2', [user.id, deviceName]);
    }

    const token = jwt.sign({ userId: user.id, username: username.toLowerCase() }, JWT_SECRET, { expiresIn: '30d' });
    res.cookie('token', token, { httpOnly: true, secure: true, sameSite: 'strict', maxAge: 30*24*60*60*1000 });
    res.json({ ok: true, username: username.toLowerCase() });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ ok: true });
});

app.get('/api/auth/me', auth, async (req, res) => {
  res.json({ username: req.user.username, userId: req.user.userId });
});

// ── Change master password ────────────────────────────────────────────────────
// Client re-encrypts every entry with the new vault key before calling this.
// Payload: { currentPassword, newPassword, entries: [{id, password_enc, iv, username_enc, username_iv, notes_enc, notes_iv}] }
app.post('/api/auth/change-password', auth, async (req, res) => {
  const { currentPassword, newPassword, entries } = req.body;
  if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Both passwords required' });
  if (newPassword.length < 8) return res.status(400).json({ error: 'New password must be at least 8 characters' });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const userResult = await client.query('SELECT password_hash FROM users WHERE id=$1', [req.user.userId]);
    const valid = await bcrypt.compare(currentPassword, userResult.rows[0].password_hash);
    if (!valid) {
      await client.query('ROLLBACK');
      return res.status(401).json({ error: 'Current password is incorrect' });
    }

    const newHash = await bcrypt.hash(newPassword, 12);
    await client.query('UPDATE users SET password_hash=$1 WHERE id=$2', [newHash, req.user.userId]);

    if (Array.isArray(entries) && entries.length) {
      for (const e of entries) {
        await client.query(
          `UPDATE vault_entries SET
             password_enc=$1, iv=$2,
             username_enc=$3, username_iv=$4,
             notes_enc=$5, notes_iv=$6,
             updated_at=NOW()
           WHERE id=$7 AND user_id=$8`,
          [e.password_enc, e.iv,
           e.username_enc||null, e.username_iv||null,
           e.notes_enc||null, e.notes_iv||null,
           e.id, req.user.userId]
        );
      }
    }

    await client.query('COMMIT');
    res.json({ ok: true });
  } catch (e) {
    await client.query('ROLLBACK');
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  } finally {
    client.release();
  }
});

// ── Vault entries ─────────────────────────────────────────────────────────────
app.get('/api/entries', auth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, site, username_enc, username_iv, password_enc, iv,
              notes_enc, notes_iv, labels, color, pinned, folder,
              updated_at, created_at
       FROM vault_entries
       WHERE user_id=$1
       ORDER BY pinned DESC, folder ASC, site ASC`,
      [req.user.userId]
    );
    res.json({ entries: result.rows });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/entries', auth, async (req, res) => {
  const { site, username_enc, username_iv, password_enc, iv,
          notes_enc, notes_iv, labels, color, pinned, folder } = req.body;
  if (!site || !password_enc || !iv) return res.status(400).json({ error: 'site, password_enc, iv required' });

  const labelsArr = Array.isArray(labels) ? labels.filter(Boolean) : [];
  const folderStr = (folder || '').trim().replace(/\/+$/, '');

  try {
    const result = await pool.query(
      `INSERT INTO vault_entries
         (user_id, site, username_enc, username_iv, password_enc, iv,
          notes_enc, notes_iv, labels, color, pinned, folder)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
       RETURNING id, updated_at`,
      [req.user.userId, site,
       username_enc||null, username_iv||null,
       password_enc, iv,
       notes_enc||null, notes_iv||null,
       labelsArr, color||'default', pinned||false, folderStr]
    );
    res.status(201).json({ id: result.rows[0].id, updated_at: result.rows[0].updated_at });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/entries/:id', auth, async (req, res) => {
  const { site, username_enc, username_iv, password_enc, iv,
          notes_enc, notes_iv, labels, color, pinned, folder } = req.body;

  const labelsArr = Array.isArray(labels) ? labels.filter(Boolean) : [];
  const folderStr = (folder || '').trim().replace(/\/+$/, '');

  try {
    const result = await pool.query(
      `UPDATE vault_entries SET
         site=$1, username_enc=$2, username_iv=$3,
         password_enc=$4, iv=$5,
         notes_enc=$6, notes_iv=$7,
         labels=$8, color=$9, pinned=$10, folder=$11,
         updated_at=NOW()
       WHERE id=$12 AND user_id=$13
       RETURNING id`,
      [site, username_enc||null, username_iv||null,
       password_enc, iv,
       notes_enc||null, notes_iv||null,
       labelsArr, color||'default', pinned||false, folderStr,
       req.params.id, req.user.userId]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Not found' });
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.patch('/api/entries/:id', auth, async (req, res) => {
  const fields = [];
  const values = [];
  let idx = 1;

  if (typeof req.body.pinned === 'boolean') { fields.push(`pinned=$${idx++}`);  values.push(req.body.pinned); }
  if (typeof req.body.color  === 'string')  { fields.push(`color=$${idx++}`);   values.push(req.body.color); }
  if (typeof req.body.folder === 'string')  { fields.push(`folder=$${idx++}`);  values.push(req.body.folder.trim().replace(/\/+$/, '')); }
  if (Array.isArray(req.body.labels))       { fields.push(`labels=$${idx++}`);  values.push(req.body.labels.filter(Boolean)); }

  if (!fields.length) return res.status(400).json({ error: 'Nothing to update' });

  fields.push('updated_at=NOW()');
  values.push(req.params.id, req.user.userId);

  try {
    const result = await pool.query(
      `UPDATE vault_entries SET ${fields.join(', ')}
       WHERE id=$${idx} AND user_id=$${idx + 1} RETURNING id`,
      values
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Not found' });
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/entries/:id', auth, async (req, res) => {
  try {
    await pool.query('DELETE FROM vault_entries WHERE id=$1 AND user_id=$2', [req.params.id, req.user.userId]);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// ── Devices ──────────────────────────────────────────────────────────────────
app.get('/api/devices', auth, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, name, last_seen, created_at FROM devices WHERE user_id=$1 ORDER BY last_seen DESC',
      [req.user.userId]
    );
    res.json({ devices: result.rows });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/devices/:id', auth, async (req, res) => {
  try {
    await pool.query('DELETE FROM devices WHERE id=$1 AND user_id=$2', [req.params.id, req.user.userId]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ── Catch-all → SPA ──────────────────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── Start ─────────────────────────────────────────────────────────────────────
initDB().then(() => {
  app.listen(PORT, () => console.log(`🔐 PassVault running on port ${PORT}`));
}).catch(e => {
  console.error('❌ DB init failed:', e.message);
  process.exit(1);
});