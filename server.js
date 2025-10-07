import express from 'express';
import session from 'express-session';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcryptjs';
import pkg from 'pg';
import path from 'path';
import dotenv from 'dotenv';

dotenv.config();
const { Pool } = pkg;

const app = express();
const PORT = process.env.PORT || 3000;
const __dirname = path.resolve();

const PUBLIC_DIR = path.join(__dirname, 'public');

// --- PostgreSQL pool ---
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false } // для Neon
});

// --- Middleware ---
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(PUBLIC_DIR));

const S_SECRET = process.env.SESSION_SECRET || 'please-change-this-secret';
app.use(session({
  name: 's7avelii.sid',
  secret: S_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 1000 * 60 * 60 * 24 * 7
  }
}));

// --- Helpers ---
function withoutPassword(user) {
  const { password, ...rest } = user;
  return rest;
}

function makeId() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
}

// --- DB Init ---
async function ensureTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      fio TEXT NOT NULL,
      phone TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE,
      password TEXT NOT NULL,
      card_number TEXT,
      card_type TEXT,
      dob TEXT,
      gender TEXT,
      avatar TEXT,
      bonus_miles INT DEFAULT 0,
      role TEXT DEFAULT 'user',
      cart JSONB DEFAULT '[]',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);
}

// --- Auth & Users ---
app.post('/api/register', async (req, res) => {
  try {
    const { fio, phone, email, password, cardNumber, cardType, dob, gender } = req.body;
    if (!fio || !phone || !password) return res.status(400).json({ error: 'fio, phone и password обязательны' });

    const hashed = await bcrypt.hash(password, 10);
    const id = makeId();

    const { rowCount } = await pool.query(
      `INSERT INTO users(id,fio,phone,email,password,card_number,card_type,dob,gender)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
      [id, fio, phone, email || '', hashed, cardNumber || '', cardType || '', dob || '', gender || '']
    );

    req.session.userId = id;
    res.json({ ok: true, user: { id, fio, phone, email, cardNumber, cardType, dob, gender } });
  } catch (err) {
    console.error(err);
    if (err.code === '23505') return res.status(400).json({ error: 'Пользователь с таким email или телефоном уже существует' });
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { phone, email, password } = req.body;
    if ((!phone && !email) || !password) return res.status(400).json({ error: 'Нужен phone или email и пароль' });

    const { rows } = await pool.query(
      `SELECT * FROM users WHERE phone=$1 OR email=$2 LIMIT 1`,
      [phone || '', email || '']
    );
    const user = rows[0];
    if (!user) return res.status(400).json({ error: 'Пользователь не найден' });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(400).json({ error: 'Неверный пароль' });

    req.session.userId = user.id;
    res.json({ ok: true, user: withoutPassword(user) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) console.warn(err);
    res.clearCookie('s7avelii.sid');
    res.json({ ok: true });
  });
});

app.get('/api/profile', async (req, res) => {
  try {
    if (!req.session.userId) return res.status(401).json({ error: 'Не авторизован' });
    const { rows } = await pool.query(`SELECT * FROM users WHERE id=$1 LIMIT 1`, [req.session.userId]);
    const user = rows[0];
    if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
    res.json({ ok: true, user: withoutPassword(user) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// --- Cart API ---
app.post('/api/cart/add', async (req, res) => {
  try {
    if (!req.session.userId) return res.status(401).json({ error: 'Не авторизован' });
    const item = { id: makeId(), addedAt: new Date().toISOString(), ...req.body };

    await pool.query(
      `UPDATE users SET cart = COALESCE(cart,'[]')::jsonb || $1::jsonb WHERE id=$2`,
      [JSON.stringify([item]), req.session.userId]
    );

    const { rows } = await pool.query(`SELECT cart FROM users WHERE id=$1`, [req.session.userId]);
    res.json({ ok: true, cart: rows[0].cart });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/cart', async (req, res) => {
  try {
    if (!req.session.userId) return res.status(401).json({ error: 'Не авторизован' });
    const { rows } = await pool.query(`SELECT cart FROM users WHERE id=$1`, [req.session.userId]);
    res.json({ ok: true, cart: rows[0]?.cart || [] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// --- SPA fallback ---
app.get('*', (req, res) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ error: 'API not found' });
  const indexFile = path.join(PUBLIC_DIR, 'index.html');
  res.sendFile(indexFile);
});

// --- Start ---
(async () => {
  try {
    await ensureTables();
    app.listen(PORT, () => console.log(`Server listening on ${PORT}`));
  } catch (err) {
    console.error('Failed to start', err);
    process.exit(1);
  }
})();
