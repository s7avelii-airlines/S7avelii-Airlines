// server.cjs (CommonJS — запускай `node server.cjs`)
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


// --- Настройки ---
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || 'change_this_secret';
const STATIC_ORIGIN = process.env.STATIC_ORIGIN || '*'; // можно указать сайт фронта

// --- Postgres pool (один для всего) ---
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_SSL === 'false' ? false : { rejectUnauthorized: false },
});

// --- Создание папки uploads ---
const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// --- Multer для загрузки файлов ---
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const safe = Date.now() + '-' + file.originalname.replace(/\s+/g, '_');
    cb(null, safe);
  }
});
const upload = multer({ storage });

// --- Express ---
const app = express();
app.use(express.json());
app.use(cors({
  origin: (origin, cb) => cb(null, true), // разрешаем любые источники
  methods: ["GET","POST","PUT","DELETE","OPTIONS"],
  allowedHeaders: ["Content-Type","Authorization","Accept"],
  credentials: true
}));
app.use('/uploads', express.static(UPLOAD_DIR));
app.use(express.static('public'));

// --- Helpers ---
function signToken(userId) {
  return jwt.sign(
    { id: userId },
    JWT_SECRET,
    { expiresIn: '30d' } // ← 30 дней
  );
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

function normalizePayload(body) {
  const out = {};
  for (const k of Object.keys(body || {})) {
    if (k === 'cardNumber') out['card_number'] = body[k];
    else if (k === 'cardType') out['card_type'] = body[k];
    else out[k] = body[k];
  }
  return out;
}

// --- SMS codes in-memory ---
const smsCodes = new Map();

// --- DB init ---
async function initDB() {
  try {
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
    await pool.query(`
      CREATE TABLE IF NOT EXISTS notifications (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        type TEXT,
        title TEXT NOT NULL,
        message TEXT NOT NULL,
        data JSONB,
        is_read BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);
await pool.query(`
  CREATE TABLE IF NOT EXISTS miles_transactions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    type TEXT,
    amount INTEGER NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT NOW()
  );
`);

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

    console.log('DB ready');
  } catch (err) {
    console.error('DB init failed', err);
  }
}
initDB();

// --- Routes ---

// Health
app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});



// =======================
// REQUEST CODE
// =======================
// ===== REQUEST SMS CODE =====
app.post('/api/auth/request-code', async (req, res) => {
  try {

    let { phone } = req.body;

    if (!phone)
      return res.status(400).json({ error: 'Телефон обязателен' });

    // приводим к формату 79626298105
    phone = phone.replace(/\D/g, '');

    if (phone.startsWith('8'))
      phone = '7' + phone.slice(1);

    if (!phone.startsWith('7') || phone.length !== 11)
      return res.status(400).json({ error: 'Неверный формат телефона' });

    // генерируем код
    const code = Math.floor(1000 + Math.random() * 9000).toString();

    console.log(`SMS CODE для ${phone}: ${code}`);

    // сохраняем код в БД
    await pool.query(`
      INSERT INTO sms_codes (phone, code, created_at)
      VALUES ($1,$2,NOW())
      ON CONFLICT (phone)
      DO UPDATE SET
        code = EXCLUDED.code,
        created_at = NOW()
    `, [phone, code]);


    // отправляем SMS БЕЗ await (максимально быстро)
    const url =
      `https://sms.ru/sms/send?api_id=${process.env.SMSRU_API_KEY}` +
      `&to=${phone}` +
      `&msg=${encodeURIComponent("S7avelii: код входа " + code)}` +
      `&json=1`;

    fetch(url)
      .then(r => r.json())
      .then(data => {
        console.log("SMS RU RESPONSE:", data);
      })
      .catch(err => {
        console.log("SMS ERROR:", err.message);
      });


    // сразу отвечаем клиенту
    res.json({ ok: true });

  }
  catch (err) {

    console.log('request-code err', err);

    res.status(500).json({
      error: 'Ошибка отправки кода'
    });

  }
});


// =======================
// VERIFY CODE
// =======================
app.post('/api/auth/verify-code', async (req, res) => {

  try {

    let { phone, code } = req.body;

    phone = phone.replace(/\D/g, '');

    const result = await pool.query(
      `SELECT * FROM sms_codes WHERE phone=$1`,
      [phone]
    );

    if (!result.rows.length)
      return res.status(400).json({
        error: 'Код не найден'
      });

    if (result.rows[0].code !== code)
      return res.status(400).json({
        error: 'Неверный код'
      });


    const user = await pool.query(
      `SELECT * FROM users WHERE phone=$1`,
      [phone]
    );

    if (!user.rows.length)
      return res.status(400).json({
        error: 'Пользователь не найден'
      });


    const token = jwt.sign(
      { id: user.rows[0].id },
      process.env.JWT_SECRET,
      { expiresIn: '30d' }
    );


    res.json({
      token,
      fio: user.rows[0].fio
    });

  }
  catch (err) {

    console.log('verify-code err', err);

    res.status(500).json({
      error: 'Ошибка'
    });

  }

});



// Register
app.post('/api/register', async (req, res) => {
  try {
    const { fio, email, phone, password, dob, gender, cardNumber, cardType } = req.body;
    if (!fio || !phone || !password) {
  return res.status(400).json({ error: "fio,phone,password required" });
}

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

app.post('/api/auth/login', async (req,res)=>{
  try{
    const {phone,password}=req.body;
    if(!phone||!password)
      return res.status(400).json({error:'Данные обязательны'});

    const normalized=phone.replace(/\D/g,'');

    const r=await pool.query(
      'SELECT id,fio,password FROM users WHERE phone=$1',
      [normalized]
    );

    const user=r.rows[0];
    if(!user) return res.status(404).json({error:'Пользователь не найден'});

    const ok=await bcrypt.compare(password,user.password);
    if(!ok) return res.status(400).json({error:'Неверный пароль'});

    const token=signToken(user.id);
    res.json({token});
  }catch(e){
    res.status(500).json({error:'Login error'});
  }
});


// Profile
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

app.put('/api/profile', authMiddleware, async (req, res) => {
  try {
    const raw = normalizePayload(req.body);
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

// Avatar upload
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

// Shop
app.get('/api/shop', async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM products ORDER BY id');
    res.json({ products: r.rows });
  } catch (err) {
    console.error('shop err', err);
    res.status(500).json({ error: 'Shop error' });
  }
});

// Checkout
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


// --- Routes ---

app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ ok: false });
  }
});

// =======================
// TOPUP MILES
// =======================
app.post('/api/miles/topup', async (req, res) => {
  try {
    let { card_number, amount, description } = req.body;

    if (!card_number)
      return res.status(400).json({ error: 'card_number обязателен' });

    amount = Math.floor(Number(amount));
    if (amount <= 0)
      return res.status(400).json({ error: 'Некорректное количество миль' });

    const userRes = await pool.query(
      'SELECT id, bonus_miles FROM users WHERE card_number=$1',
      [card_number]
    );

    if (!userRes.rows.length)
      return res.status(404).json({ error: 'Карта не найдена' });

    const user = userRes.rows[0];

    await pool.query(
      `INSERT INTO miles_transactions (user_id, type, amount, description)
       VALUES ($1,$2,$3,$4)`,
      [user.id, 'topup', amount, description || 'Пополнение миль']
    );

    await pool.query(
      `UPDATE users 
       SET bonus_miles = COALESCE(bonus_miles,0) + $1 
       WHERE id=$2`,
      [amount, user.id]
    );

    res.json({
      ok: true,
      new_balance: user.bonus_miles + amount
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Ошибка пополнения миль' });
  }
});

// =======================
// COMMAND
// =======================
app.post('/api/miles/command', async (req, res) => {
  try {
    const parsed = parseCommand(req.body.text);

    if (!parsed)
      return res.status(400).json({ error: 'Команда не распознана' });

    const userRes = await pool.query(
      'SELECT id FROM users WHERE card_number=$1',
      [parsed.card_number]
    );

    if (!userRes.rows.length)
      return res.status(404).json({ error: 'Карта не найдена' });

    const user = userRes.rows[0];

    await pool.query(
      `INSERT INTO miles_transactions (user_id, type, amount, description)
       VALUES ($1,$2,$3,$4)`,
      [user.id, 'topup', parsed.amount, 'Пополнение через команду']
    );

    await pool.query(
      `UPDATE users 
       SET bonus_miles = COALESCE(bonus_miles,0) + $1 
       WHERE id=$2`,
      [parsed.amount, user.id]
    );

    res.json({ ok: true });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Ошибка команды' });
  }
});

// =======================
// HISTORY
// =======================
app.get('/api/miles/history/:card', async (req, res) => {
  try {
    const card_number = req.params.card;

    const userRes = await pool.query(
      'SELECT id FROM users WHERE card_number=$1',
      [card_number]
    );

    if (!userRes.rows.length)
      return res.status(404).json({ error: 'Карта не найдена' });

    const history = await pool.query(
      `SELECT id, type, amount, description, created_at
       FROM miles_transactions
       WHERE user_id=$1
       ORDER BY created_at DESC`,
      [userRes.rows[0].id]
    );

    res.json(history.rows);

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Ошибка истории' });
  }
});
// Пополнение милей
app.post('/api/miles/topup', authMiddleware, async (req, res) => {
  try {
    const { cardNumber, amount } = req.body;
    if (!cardNumber || !amount) return res.status(400).json({ error: 'cardNumber и amount обязательны' });

    // Находим пользователя по карте
    const { rows } = await pool.query('SELECT id, bonus_miles FROM users WHERE card_number=$1', [cardNumber]);
    if (!rows.length) return res.status(404).json({ error: 'Пользователь не найден' });

    const userId = rows[0].id;
    const newMiles = (rows[0].bonus_miles || 0) + Number(amount);

    // Обновляем мили
    await pool.query('UPDATE users SET bonus_miles=$1 WHERE id=$2', [newMiles, userId]);

    // Добавляем запись в блок пополнений (можно в notifications или отдельную таблицу)
    await pool.query(
      'INSERT INTO notifications (user_id, type, title, message) VALUES ($1,$2,$3,$4)',
      [userId, 'miles_topup', `Пополнение ${amount} миль`, `Счёт вашей карты пополнен на ${amount} миль.`]
    );

    res.json({ ok: true, newMiles });

  } catch (err) {
    console.error('topup err', err);
    res.status(500).json({ error: 'Ошибка начисления милей' });
  }
});



// Notifications
app.get('/notifications/unread-count', authMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT COUNT(*) AS cnt FROM notifications WHERE user_id=$1 AND is_read=false',
      [req.userId]
    );
    res.json({ unread: Number(rows[0].cnt) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'db error' });
  }
});

app.get('/notifications', authMiddleware, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit || '20'), 100);
    const offset = parseInt(req.query.offset || '0');
    const { rows } = await pool.query(
      'SELECT * FROM notifications WHERE user_id=$1 ORDER BY created_at DESC LIMIT $2 OFFSET $3',
      [req.userId, limit, offset]
    );
    res.json({ items: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'db error' });
  }
});

app.post('/notifications/mark-read', authMiddleware, async (req, res) => {
  try {
    const ids = req.body.ids;
    if (!Array.isArray(ids) || !ids.length) return res.status(400).json({ error: 'ids required' });

    const placeholders = ids.map((_, idx) => `$${idx+2}`).join(',');
    await pool.query(`UPDATE notifications SET is_read=true WHERE user_id=$1 AND id IN (${placeholders})`, [req.userId, ...ids]);

    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'db error' });
  }
});

app.post('/notifications/add', async (req, res) => {
  try {
    const { user_id, title, message, type = null, data = null } = req.body;
    if (!user_id || !title) return res.status(400).json({ error: 'user_id and title required' });

    await pool.query(
      'INSERT INTO notifications (user_id, type, title, message, data) VALUES ($1,$2,$3,$4,$5)',
      [user_id, type, title, message, data ? JSON.stringify(data) : null]
    );
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'db error' });
  }
});

// Простой health endpoint
app.get('/health', (req, res) => res.json({ ok: true }));

// --- Start server ---
app.listen(PORT, () => console.log(`✅ Server running on ${PORT}`));

