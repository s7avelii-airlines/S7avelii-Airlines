// server.js
const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const PgSession = require('connect-pg-simple')(session);
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// PostgreSQL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL, // neon db url
  ssl: { rejectUnauthorized: false }
});

app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// session store in PostgreSQL
const S_SECRET = process.env.SESSION_SECRET || 'please-change-this-secret';
app.use(session({
  store: new PgSession({
    pool: pool,
    tableName: 'session'
  }),
  name: 's7avelii.sid',
  secret: S_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
  }
}));

/* ---------- Helpers ---------- */
function makeId() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
}

function withoutPassword(user) {
  const copy = { ...user };
  delete copy.password;
  return copy;
}

/* ---------- User/Auth API ---------- */

// Register
app.post('/api/register', async (req, res) => {
  try {
    const { fio, phone, email, password, cardNumber, cardType, dob, gender } = req.body;
    if (!fio || !phone || !password) return res.status(400).json({ error: 'fio, phone и password обязательны' });

    const client = await pool.connect();
    try {
      const { rows } = await client.query('SELECT * FROM users WHERE phone=$1 OR (email=$2 AND $2<>\'\')', [phone, email]);
      if (rows.length > 0) return res.status(400).json({ error: 'Пользователь с таким телефоном/email уже есть' });

      const hashed = await bcrypt.hash(password, 10);
      const id = makeId();

      const result = await client.query(
        `INSERT INTO users (id, fio, phone, email, password, card_number, card_type, dob, gender, avatar, bonus_miles, role, created_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,0,'user',NOW()) RETURNING *`,
        [id, fio, phone, email || '', hashed, cardNumber || '', cardType || '', dob || '', gender || '', '']
      );

      const user = result.rows[0];
      req.session.userId = user.id;
      res.json({ ok: true, user: withoutPassword(user) });
    } finally { client.release(); }
  } catch (err) {
    console.error('register error', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { phone, email, password } = req.body;
    if ((!phone && !email) || !password) return res.status(400).json({ error: 'Нужен phone/email и пароль' });

    const client = await pool.connect();
    try {
      const { rows } = await client.query(
        'SELECT * FROM users WHERE phone=$1 OR (email=$2 AND $2<>\'\')', 
        [phone, email]
      );
      if (rows.length === 0) return res.status(400).json({ error: 'Пользователь не найден' });

      const user = rows[0];
      const ok = await bcrypt.compare(password, user.password);
      if (!ok) return res.status(400).json({ error: 'Неверный пароль' });

      req.session.userId = user.id;
      res.json({ ok: true, user: withoutPassword(user) });
    } finally { client.release(); }
  } catch (err) {
    console.error('login error', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Logout
app.post('/api/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) console.warn('session destroy error', err);
    res.clearCookie('s7avelii.sid');
    res.json({ ok: true });
  });
});

// Get profile
app.get('/api/profile', async (req, res) => {
  try {
    if (!req.session.userId) return res.status(401).json({ error: 'Не авторизован' });
    const { rows } = await pool.query('SELECT * FROM users WHERE id=$1', [req.session.userId]);
    if (rows.length === 0) return res.status(404).json({ error: 'Пользователь не найден' });
    res.json({ ok: true, user: withoutPassword(rows[0]) });
  } catch (err) {
    console.error('profile error', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update profile
app.post(['/api/profile/update', '/api/update-profile'], async (req, res) => {
  try {
    if (!req.session.userId) return res.status(401).json({ error: 'Не авторизован' });

    const allowed = ['fio','phone','email','cardNumber','cardType','dob','gender','avatar','bonusMiles'];
    const updates = [];
    const values = [];
    let i = 1;
    for (const k of allowed) {
      if (req.body[k] !== undefined) {
        updates.push(`${k === 'cardNumber' ? 'card_number' : k}=$${i}`);
        values.push(req.body[k]);
        i++;
      }
    }
    if (updates.length === 0) return res.json({ ok: true });

    values.push(req.session.userId);
    const query = `UPDATE users SET ${updates.join(', ')} WHERE id=$${i} RETURNING *`;
    const { rows } = await pool.query(query, values);
    res.json({ ok: true, user: withoutPassword(rows[0]) });
  } catch (err) {
    console.error('profile update error', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/* ---------- SPA fallback ---------- */
app.get('*', (req, res) => {
  const indexFile = path.join(__dirname, 'public', 'index.html');
  res.sendFile(indexFile);
});

/* ---------- Start ---------- */
app.listen(PORT, () => {
  console.log(`Server listening on ${PORT}`);
});
