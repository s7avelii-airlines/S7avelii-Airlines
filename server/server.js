// server.js (CommonJS) — финальный рабочий сервер
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const PgSession = require('connect-pg-simple')(session);
const path = require('path');

const PORT = process.env.PORT || 10000;
const NODE_ENV = process.env.NODE_ENV || 'development';
const FRONT = process.env.CORS_ORIGIN || '*';

if (!process.env.DATABASE_URL) {
  console.error('FATAL: DATABASE_URL not set in env');
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

pool.on('error', (err) => {
  console.error('Unexpected pg pool error', err);
});

// express
const app = express();
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true }));

app.use(cors({
  origin: FRONT,
  credentials: true
}));

// session store in Postgres
app.use(session({
  store: new PgSession({
    pool: pool,
    tableName: 'session'
  }),
  name: 's7avelii.sid',
  secret: process.env.SESSION_SECRET || 'change_this_secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: NODE_ENV === 'production',
    httpOnly: true,
    sameSite: NODE_ENV === 'production' ? 'none' : 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
}));

/* ---------- DB init: create tables if not exists ---------- */
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS session (
      sid varchar NOT NULL COLLATE "default",
      sess json NOT NULL,
      expire timestamp(6) NOT NULL,
      PRIMARY KEY (sid)
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      fio TEXT,
      phone TEXT UNIQUE,
      email TEXT UNIQUE,
      password TEXT,
      dob TEXT,
      gender TEXT,
      card_number TEXT,
      card_type TEXT,
      avatar TEXT,
      vk TEXT,
      telegram TEXT,
      bonus_miles INTEGER DEFAULT 0,
      status_miles INTEGER DEFAULT 0,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS products (
      id SERIAL PRIMARY KEY,
      name TEXT,
      price INTEGER
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS cart (
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      product_id INTEGER,
      name TEXT,
      price INTEGER,
      qty INTEGER DEFAULT 1,
      PRIMARY KEY (user_id, product_id)
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS orders (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id),
      items JSONB,
      total INTEGER,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);

  // seed products if empty
  const { rows } = await pool.query("SELECT COUNT(*) FROM products");
  if (Number(rows[0].count) === 0) {
    await pool.query(`
      INSERT INTO products (name, price) VALUES
        ('Брелок S7avelii', 500),
        ('Футболка S7avelii', 1200),
        ('Кружка S7avelii', 800),
        ('Модель самолёта', 2500)
    `);
    console.log('Seeded products');
  }

  console.log('DB init ok');
}

/* ---------- Helpers ---------- */
function safeUser(u) {
  if (!u) return null;
  const copy = { ...u };
  delete copy.password;
  return copy;
}

/* ---------- Routes ---------- */

// health / DB test
app.get('/api/test-db', async (req, res) => {
  try {
    const r = await pool.query('SELECT NOW() as now');
    res.json({ ok: true, now: r.rows[0].now });
  } catch (err) {
    console.error('test-db err:', err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// register
app.post('/api/register', async (req, res) => {
  try {
    const { fio, phone, email, password, cardNumber, cardType, dob, gender } = req.body;
    if (!password || (!phone && !email) || !fio) {
      return res.status(400).json({ error: 'fio, (phone or email) and password required' });
    }

    // unique checks
    if (phone) {
      const { rows } = await pool.query('SELECT id FROM users WHERE phone=$1', [phone]);
      if (rows.length) return res.status(400).json({ error: 'Phone already registered' });
    }
    if (email) {
      const { rows } = await pool.query('SELECT id FROM users WHERE email=$1', [email]);
      if (rows.length) return res.status(400).json({ error: 'Email already registered' });
    }

    const hashed = await bcrypt.hash(password, 10);
    const r = await pool.query(
      `INSERT INTO users (fio, phone, email, password, dob, gender, card_number, card_type)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
      [fio, phone || null, email || null, hashed, dob || null, gender || null, cardNumber || null, cardType || null]
    );

    req.session.userId = r.rows[0].id;
    res.json({ ok: true, user: safeUser(r.rows[0]) });
  } catch (err) {
    console.error('register err:', err);
    res.status(500).json({ error: 'Registration failed', details: err.message });
  }
});

// login (phone or email)
app.post('/api/login', async (req, res) => {
  try {
    const { phone, email, password } = req.body;
    if ((!phone && !email) || !password) return res.status(400).json({ error: 'Need phone/email + password' });

    const q = phone ? 'SELECT * FROM users WHERE phone=$1' : 'SELECT * FROM users WHERE email=$1';
    const param = phone || email;
    const { rows } = await pool.query(q, [param]);
    const user = rows[0];
    if (!user) return res.status(400).json({ error: 'User not found' });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(400).json({ error: 'Wrong password' });

    req.session.userId = user.id;
    res.json({ ok: true, user: safeUser(user) });
  } catch (err) {
    console.error('login err:', err);
    res.status(500).json({ error: 'Login failed', details: err.message });
  }
});

// logout
app.post('/api/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) console.warn('session destroy err', err);
    res.clearCookie('s7avelii.sid', { path: '/' });
    res.json({ ok: true });
  });
});

// profile
app.get('/api/profile', async (req, res) => {
  try {
    if (!req.session.userId) return res.status(401).json({ error: 'Not authenticated' });
    const { rows } = await pool.query('SELECT * FROM users WHERE id=$1', [req.session.userId]);
    res.json({ ok: true, user: safeUser(rows[0]) });
  } catch (err) {
    console.error('profile err:', err);
    res.status(500).json({ error: 'Profile error', details: err.message });
  }
});

app.post('/api/profile/update', async (req, res) => {
  try {
    if (!req.session.userId) return res.status(401).json({ error: 'Not authenticated' });
    const allowed = ['fio','phone','email','dob','gender','card_number','card_type','avatar','bonus_miles','status_miles','vk','telegram','password'];
    const updates = [];
    const values = [];
    let i = 1;
    for (const k of allowed) {
      if (req.body[k] !== undefined) {
        if (k === 'password') {
          const hashed = await bcrypt.hash(req.body.password, 10);
          updates.push(`password=$${i++}`);
          values.push(hashed);
        } else {
          updates.push(`${k}=$${i++}`);
          values.push(req.body[k]);
        }
      }
    }
    if (!updates.length) return res.json({ ok: true });
    values.push(req.session.userId);
    await pool.query(`UPDATE users SET ${updates.join(',')} WHERE id=$${values.length}`, values);
    const { rows } = await pool.query('SELECT * FROM users WHERE id=$1', [req.session.userId]);
    res.json({ ok: true, user: safeUser(rows[0]) });
  } catch (err) {
    console.error('profile update err:', err);
    res.status(500).json({ error: 'Update failed', details: err.message });
  }
});

/* Products */
app.get('/api/products', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM products ORDER BY id');
    res.json(rows);
  } catch (err) {
    console.error('products err:', err);
    res.status(500).json({ error: 'Products error' });
  }
});

/* Cart */
app.get('/api/cart', async (req, res) => {
  try {
    if (!req.session.userId) return res.json([]);
    const { rows } = await pool.query('SELECT product_id as id, name, price, qty FROM cart WHERE user_id=$1', [req.session.userId]);
    res.json(rows);
  } catch (err) {
    console.error('cart get err:', err);
    res.status(500).json({ error: 'Cart error' });
  }
});

app.post('/api/cart/add', async (req, res) => {
  try {
    if (!req.session.userId) return res.status(401).json({ error: 'Not authenticated' });
    const { id: productId, qty = 1 } = req.body;
    const p = await pool.query('SELECT * FROM products WHERE id=$1', [productId]);
    if (!p.rows.length) return res.status(404).json({ error: 'Product not found' });
    const prod = p.rows[0];
    await pool.query(`
      INSERT INTO cart (user_id, product_id, name, price, qty)
      VALUES ($1,$2,$3,$4,$5)
      ON CONFLICT (user_id, product_id) DO UPDATE SET qty = cart.qty + EXCLUDED.qty
    `, [req.session.userId, prod.id, prod.name, prod.price, qty]);
    res.json({ ok: true });
  } catch (err) {
    console.error('cart add err:', err);
    res.status(500).json({ error: 'Add to cart failed' });
  }
});

app.post('/api/cart/remove', async (req, res) => {
  try {
    if (!req.session.userId) return res.status(401).json({ error: 'Not authenticated' });
    const { id: productId } = req.body;
    await pool.query('DELETE FROM cart WHERE user_id=$1 AND product_id=$2', [req.session.userId, productId]);
    res.json({ ok: true });
  } catch (err) {
    console.error('cart remove err:', err);
    res.status(500).json({ error: 'Remove failed' });
  }
});

app.post('/api/cart/checkout', async (req, res) => {
  try {
    if (!req.session.userId) return res.status(401).json({ error: 'Not authenticated' });
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const cartRes = await client.query('SELECT product_id, name, price, qty FROM cart WHERE user_id=$1', [req.session.userId]);
      const items = cartRes.rows;
      if (!items.length) { await client.query('ROLLBACK'); return res.status(400).json({ error: 'Cart empty' }); }
      const total = items.reduce((s, it) => s + (it.price * it.qty), 0);
      await client.query('INSERT INTO orders (user_id, items, total) VALUES ($1,$2,$3)', [req.session.userId, JSON.stringify(items), total]);
      await client.query('DELETE FROM cart WHERE user_id=$1', [req.session.userId]);
      const milesToAdd = Math.floor(total / 10);
      await client.query('UPDATE users SET bonus_miles = bonus_miles + $1 WHERE id=$2', [milesToAdd, req.session.userId]);
      await client.query('COMMIT');
      res.json({ ok: true, total, milesAdded: milesToAdd });
    } catch (txErr) {
      await client.query('ROLLBACK');
      throw txErr;
    } finally {
      client.release();
    }
  } catch (err) {
    console.error('checkout err:', err);
    res.status(500).json({ error: 'Checkout failed' });
  }
});

/* Orders */
app.get('/api/orders', async (req, res) => {
  try {
    if (!req.session.userId) return res.json([]);
    const { rows } = await pool.query('SELECT id, items, total, created_at FROM orders WHERE user_id=$1 ORDER BY id DESC', [req.session.userId]);
    res.json(rows);
  } catch (err) {
    console.error('orders err:', err);
    res.status(500).json({ error: 'Orders error' });
  }
});

/* Miles */
app.get('/api/miles', async (req, res) => {
  try {
    if (!req.session.userId) return res.status(401).json({ error: 'Not authenticated' });
    const { rows } = await pool.query('SELECT bonus_miles, status_miles FROM users WHERE id=$1', [req.session.userId]);
    res.json(rows[0] || { bonus_miles: 0, status_miles: 0 });
  } catch (err) {
    console.error('miles err:', err);
    res.status(500).json({ error: 'Miles error' });
  }
});

/* SPA fallback - serve index if you want to host static from this service (optional) */
const PUBLIC_DIR = path.join(__dirname, '..', 'public'); // если статика в ../public
// app.use(express.static(PUBLIC_DIR));
// app.get('*', (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'index.html')));

app.listen(PORT, async () => {
  console.log(`✅ Server started on ${PORT}`);
  try {
    await initDB();
  } catch (err) {
    console.error('DB init failed:', err);
    process.exit(1);
  }
});
