// server.cjs  (CommonJS — запускай `node server.cjs`)
const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { Pool } = require('pg');

dotenv.config();

const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || 'change_this_secret';
const STATIC_ORIGIN = process.env.STATIC_ORIGIN || '*'; // можно указать сайт фронта

// Postgres pool (Render/Neon-friendly)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_SSL === 'false' ? false : { rejectUnauthorized: false },
});

// Ensure uploads dir
const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// Multer
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const safe = Date.now() + '-' + file.originalname.replace(/\s+/g, '_');
    cb(null, safe);
  }
});
const upload = multer({ storage });

// Express
const app = express();
app.use(express.json());
app.use(cors({
  origin: (origin, cb) => { cb(null, true); }, // разрешаем любые источники; для продакшн укажи конкретный домен
  methods: ["GET","POST","PUT","DELETE","OPTIONS"],
  allowedHeaders: ["Content-Type","Authorization","Accept"],
  credentials: true
}));
app.use('/uploads', express.static(UPLOAD_DIR));

// --- DB init ---
async function initDB() {
  // create tables if not exists. Columns named to match frontend expectations.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      fio TEXT,
      full_name TEXT,
      email TEXT UNIQUE,
      phone TEXT UNIQUE,
      password TEXT,
      avatar TEXT,
      dob DATE,
      gender TEXT,
      vk TEXT,
      telegram TEXT,
      card_number TEXT,
      card_type TEXT,
      bonus_miles INTEGER DEFAULT 0,
      status_miles INTEGER DEFAULT 0,
      cart JSONB DEFAULT '[]'
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS products (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      price INTEGER NOT NULL
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS orders (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      items JSONB,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);

  // seed products
  const r = await pool.query('SELECT COUNT(*) FROM products');
  if (Number(r.rows[0].count) === 0) {
    await pool.query(`
      INSERT INTO products (name,price) VALUES
      ('Брелок S7avelii',500),
      ('Футболка S7avelii',1200),
      ('Кружка S7avelii',800),
      ('Модель самолёта',2500)
    `);
  }
}
initDB().then(()=>console.log('DB ready')).catch(err=>console.error('DB init failed', err));

// --- Helpers ---
function signToken(userId) {
  return jwt.sign({ id: userId }, JWT_SECRET, { expiresIn: '7d' });
}

async function getUserById(id) {
  const { rows } = await pool.query('SELECT id,fio,full_name,email,phone,avatar,dob,gender,card_number,card_type,bonus_miles,status_miles,cart FROM users WHERE id=$1', [id]);
  return rows[0] || null;
}

function authMiddleware(req, res, next) {
  const h = req.headers.authorization;
  if (!h) return res.status(401).json({ error: 'No token' });
  const token = h.split(' ')[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.id;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// camelCase -> snake_case mapping helper
function normalizePayload(body) {
  const out = {};
  for (const k of Object.keys(body || {})) {
    if (k === 'cardNumber') out['card_number'] = body[k];
    else if (k === 'cardType') out['card_type'] = body[k];
    else out[k] = body[k];
  }
  return out;
}

// --- Routes ---

app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// Register
app.post('/api/register', async (req, res) => {
  try {
    const { fio, email, phone, password, dob, gender, cardNumber, cardType } = req.body;
    if (!fio || !email || !password) return res.status(400).json({ error: 'fio,email,password required' });

    // check existing
    const check = await pool.query('SELECT id FROM users WHERE email=$1 OR phone=$2', [email, phone || null]);
    if (check.rows.length) return res.status(400).json({ error: 'User exists' });

    const hash = await bcrypt.hash(password, 10);
    const r = await pool.query(
      `INSERT INTO users (fio, full_name, email, phone, password, dob, gender, card_number, card_type)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id`,
      [fio, fio, email, phone || null, hash, dob || null, gender || null, cardNumber || null, cardType || null]
    );
    const id = r.rows[0].id;
    const token = signToken(id);
    const user = await getUserById(id);
    res.json({ token, user });
  } catch (err) {
    console.error('register err', err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { identifier, phone, email, password } = req.body;
    const key = identifier || phone || email;
    if (!key || !password) return res.status(400).json({ error: 'identifier/password required' });

    const r = await pool.query('SELECT * FROM users WHERE email=$1 OR phone=$1', [key]);
    const userRow = r.rows[0];
    if (!userRow) return res.status(400).json({ error: 'User not found' });

    const ok = await bcrypt.compare(password, userRow.password);
    if (!ok) return res.status(400).json({ error: 'Wrong password' });

    const token = signToken(userRow.id);
    const user = await getUserById(userRow.id);
    res.json({ token, user });
  } catch (err) {
    console.error('login err', err);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Get profile
app.get('/api/profile', authMiddleware, async (req, res) => {
  try {
    const user = await getUserById(req.userId);
    if (!user) return res.status(404).json({ error: 'Not found' });
    res.json(user);
  } catch (err) {
    console.error('profile err', err);
    res.status(500).json({ error: 'Profile error' });
  }
});

// Update profile (accepts camelCase or snake_case)
app.put('/api/profile', authMiddleware, async (req, res) => {
  try {
    const raw = normalizePayload(req.body);
    // allowed fields
    const allowed = ['fio','email','phone','dob','gender','avatar','card_number','card_type','bonus_miles','status_miles'];
    const sets = [];
    const vals = [];
    let i = 1;
    for (const k of Object.keys(raw)) {
      if (!allowed.includes(k)) continue;
      sets.push(`${k}=$${i++}`);
      vals.push(raw[k]);
    }
    if (!sets.length) return res.json({ ok: true, message: 'Nothing to update' });

    // if fio present -> also update full_name
    if ('fio' in raw) {
      sets.push(`full_name=$${i++}`);
      vals.push(raw.fio);
    }

    vals.push(req.userId);
    const sql = `UPDATE users SET ${sets.join(',')} WHERE id=$${i} RETURNING id`;
    await pool.query(sql, vals);

    const user = await getUserById(req.userId);
    res.json({ ok: true, user });
  } catch (err) {
    console.error('profile.update err', err);
    res.status(500).json({ error: 'Update failed' });
  }
});

// Upload avatar
app.post('/api/profile/avatar', authMiddleware, upload.single('avatar'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file' });
    const avatarPath = '/uploads/' + req.file.filename;
    await pool.query('UPDATE users SET avatar=$1 WHERE id=$2', [avatarPath, req.userId]);
    const user = await getUserById(req.userId);
    res.json({ avatar: avatarPath, user });
  } catch (err) {
    console.error('avatar upload err', err);
    res.status(500).json({ error: 'Avatar upload failed' });
  }
});

// Products / shop
app.get('/api/shop', async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM products ORDER BY id');
    res.json({ products: r.rows });
  } catch (err) {
    console.error('shop err', err);
    res.status(500).json({ error: 'Shop error' });
  }
});

// Checkout -> create order, clear cart and add bonus miles
app.post('/api/checkout', authMiddleware, async (req, res) => {
  try {
    const items = req.body.items || [];
    await pool.query('INSERT INTO orders (user_id, items) VALUES ($1,$2)', [req.userId, JSON.stringify(items)]);
    await pool.query("UPDATE users SET cart = '[]', bonus_miles = COALESCE(bonus_miles,0) + 100 WHERE id=$1", [req.userId]);
    res.json({ ok: true });
  } catch (err) {
    console.error('checkout err', err);
    res.status(500).json({ error: 'Checkout error' });
  }
});

// Fallback static (if you host frontend from same server)
app.use(express.static('public'));

// Start
app.listen(PORT, () => console.log(`✅ Server started on ${PORT}`));
