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
const axios = require('axios');


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

// --- SMS AUTH STORAGE (in-memory, safe for now) ---
const smsCodes = new Map();
// phone -> { code, expires }


// --- Routes ---

app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});
app.post('/api/auth/request-code', async (req, res) => {
  try {
    const { phone } = req.body;
    if (!phone) return res.status(400).json({ error: 'Телефон обязателен' });

    const code = Math.floor(1000 + Math.random() * 9000).toString();

    smsCodes.set(phone, {
      code,
      expires: Date.now() + 5 * 60 * 1000
    });

    await axios.get('https://sms.ru/sms/send', {
      params: {
        api_id: process.env.SMS_RU_KEY,
        to: phone.replace(/\D/g, ''),
        msg: `S7avelii: код входа ${code}`,
        json: 1
      }
    });

    res.json({ ok: true });
  } catch (err) {
    console.error('sms send error', err);
    res.status(500).json({ error: 'SMS error' });
  }
});
app.post('/api/auth/verify-code', async (req, res) => {
  try {
    const { phone, code } = req.body;
    if (!phone || !code) {
      return res.status(400).json({ error: 'Телефон и код обязательны' });
    }

    const record = smsCodes.get(phone);
    if (!record) return res.status(400).json({ error: 'Код не найден' });
    if (record.expires < Date.now()) {
      smsCodes.delete(phone);
      return res.status(400).json({ error: 'Код истёк' });
    }
    if (record.code !== code) {
      return res.status(400).json({ error: 'Неверный код' });
    }

    smsCodes.delete(phone);

    // ⬇️ ИЩЕМ ПОЛЬЗОВАТЕЛЯ В ТВОЕЙ БД
    const r = await pool.query(
      'SELECT id, fio FROM users WHERE phone=$1',
      [phone]
    );
    const user = r.rows[0];
    if (!user) {
      return res.status(404).json({ error: 'Пользователь не найден' });
    }

    const token = signToken(user.id);

    res.json({
      token,
      fio: user.fio
    });
  } catch (err) {
    console.error('verify code error', err);
    res.status(500).json({ error: 'Verify failed' });
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


const app = express();
app.use(cors());
app.use(bodyParser.json());

// Настройки - берём из env (Render: задаёшь в UI)
const {
  DB_HOST,
  DB_PORT = 3306,
  DB_USER,
  DB_PASSWORD,
  DB_NAME,
  JWT_SECRET // если используешь JWT
} = process.env;

// Создаём pool
const pool = mysql.createPool({
  host: DB_HOST,
  port: DB_PORT,
  user: DB_USER,
  password: DB_PASSWORD,
  database: DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

/*
  AUTH MIDDLEWARE
  - В демонстрации: пытается достать userId из JWT токена в Authorization: Bearer <token>
  - Если JWT_SECRET не задан, попробуем header 'x-user-id' для упрощённой разработки.
  Замените на вашу реальную аутентификацию.
*/
async function authMiddleware(req, res, next) {
  try {
    const auth = req.headers.authorization;
    if (auth && auth.startsWith('Bearer ') && JWT_SECRET) {
      const token = auth.split(' ')[1];
      const payload = jwt.verify(token, JWT_SECRET);
      // предполагается, что payload содержит userId
      req.userId = payload.userId || payload.id || null;
    } else if (req.headers['x-user-id']) {
      req.userId = req.headers['x-user-id'];
    } else {
      req.userId = null;
    }

    if (!req.userId) {
      return res.status(401).json({ error: 'Unauthorized: user id not provided' });
    }
    next();
  } catch (err) {
    console.error('auth error', err);
    return res.status(401).json({ error: 'Unauthorized' });
  }
}

/* ---------- API Endpoints ---------- */

/**
 * GET /notifications/unread-count
 * Возвращает число непрочитанных уведомлений для текущего пользователя
 */
app.get('/notifications/unread-count', authMiddleware, async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT COUNT(*) AS cnt FROM notifications WHERE user_id = ? AND is_read = 0',
      [req.userId]
    );
    res.json({ unread: rows[0].cnt });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'db error' });
  }
});

/**
 * GET /notifications
 * Параметры: ?limit=20&offset=0
 * Возвращает список уведомлений (по убыванию времени)
 */
app.get('/notifications', authMiddleware, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit || '20'), 100);
    const offset = parseInt(req.query.offset || '0');
    const [rows] = await pool.query(
      'SELECT id, type, title, message, data, is_read, created_at FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?',
      [req.userId, limit, offset]
    );
    res.json({ items: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'db error' });
  }
});

/**
 * POST /notifications/mark-read
 * body: { ids: [1,2,3] }  - пометить указанные уведомления прочитанными
 */
app.post('/notifications/mark-read', authMiddleware, async (req, res) => {
  try {
    const ids = req.body.ids;
    if (!Array.isArray(ids) || ids.length === 0) {
      return res.status(400).json({ error: 'ids required' });
    }
    // безопасно: передаем массив в набор
    const placeholders = ids.map(()=>'?').join(',');
    const sql = `UPDATE notifications SET is_read = 1 WHERE user_id = ? AND id IN (${placeholders})`;
    await pool.query(sql, [req.userId, ...ids]);
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'db error' });
  }
});

/**
 * POST /notifications/add
 * body: { user_id, title, message, type?, data? } - только для серверной части (можно защитить)
 */
app.post('/notifications/add', async (req, res) => {
  try {
    // В проде защищай этот endpoint (только серверные вызовы)
    const { user_id, title, message, type = null, data = null } = req.body;
    if (!user_id || !title) return res.status(400).json({ error: 'user_id and title required' });
    await pool.query('INSERT INTO notifications (user_id, type, title, message, data) VALUES (?, ?, ?, ?, ?)', [
      user_id, type, title, message, data ? JSON.stringify(data) : null
    ]);
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'db error' });
  }
});

/* простой health */
app.get('/health', (req, res) => res.json({ ok: true }));

/* запуск */
const PORT = process.env.PORT || 3000;
app.listen(PORT, ()=> console.log(`Notifications API running on ${PORT}`));

