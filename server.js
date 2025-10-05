const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const PgSession = require('connect-pg-simple')(session);
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// PostgreSQL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Session store
app.use(session({
  store: new PgSession({ pool, tableName: 'session' }),
  name: 's7avelii.sid',
  secret: process.env.SESSION_SECRET || 'change_this_secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
}));

// Helpers
function makeId() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
}
function withoutPassword(user) {
  const copy = { ...user };
  delete copy.password;
  return copy;
}

// Register
app.post('/api/register', async (req, res) => {
  try {
    const { fio, phone, email, password, cardNumber, cardType, dob, gender } = req.body;
    if (!fio || !phone || !password)
      return res.status(400).json({ error: 'ФИО, телефон и пароль обязательны' });

    const { rows: exists } = await pool.query(
      'SELECT * FROM users WHERE phone=$1 OR (email=$2 AND $2<>\'\')', [phone, email]
    );
    if (exists.length > 0)
      return res.status(400).json({ error: 'Пользователь уже существует' });

    const hashed = await bcrypt.hash(password, 10);
    const id = makeId();

    const { rows } = await pool.query(`
      INSERT INTO users (id,fio,phone,email,password,card_number,card_type,dob,gender,avatar,bonus_miles,role,created_at)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'',0,'user',NOW()) RETURNING *`,
      [id,fio,phone,email||'',hashed,cardNumber||'',cardType||'',dob||'',gender||'']
    );

    const user = rows[0];
    req.session.userId = user.id;
    res.json({ ok: true, user: withoutPassword(user) });
  } catch (err) {
    console.error('register error', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { phone, email, password } = req.body;
    if ((!phone && !email) || !password)
      return res.status(400).json({ error: 'Телефон/email и пароль обязательны' });

    const { rows } = await pool.query(
      'SELECT * FROM users WHERE phone=$1 OR (email=$2 AND $2<>\'\')', [phone, email]
    );
    if (rows.length === 0) return res.status(400).json({ error: 'Пользователь не найден' });

    const user = rows[0];
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(400).json({ error: 'Неверный пароль' });

    req.session.userId = user.id;
    res.json({ ok: true, user: withoutPassword(user) });
  } catch (err) {
    console.error('login error', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Logout
app.post('/api/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) console.warn(err);
    res.clearCookie('s7avelii.sid');
    res.json({ ok: true });
  });
});

// Profile
app.get('/api/profile', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Не авторизован' });
  const { rows } = await pool.query('SELECT * FROM users WHERE id=$1', [req.session.userId]);
  if (rows.length === 0) return res.status(404).json({ error: 'Пользователь не найден' });
  res.json({ ok: true, user: withoutPassword(rows[0]) });
});

// SPA fallback
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => console.log(`Server running on ${PORT}`));
