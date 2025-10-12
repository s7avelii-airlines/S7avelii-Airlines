// server.js
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

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'secret';
const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) throw new Error('DATABASE_URL required');

const pool = new Pool({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } });

const app = express();
app.use(cors({ origin: '*', credentials: true }));
app.use(express.json());

const AVATAR_DIR = path.join(__dirname, 'public', 'avatars');
fs.mkdirSync(AVATAR_DIR, { recursive: true });
app.use('/avatars', express.static(AVATAR_DIR));
app.use(express.static(path.join(__dirname, 'public')));

// --- JWT middleware ---
const auth = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// --- Initialize DB ---
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      fio TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      phone TEXT UNIQUE,
      password TEXT NOT NULL,
      avatar TEXT,
      dob DATE,
      gender TEXT,
      card_number TEXT,
      card_type TEXT,
      bonus_miles INT DEFAULT 0,
      status_miles INT DEFAULT 0,
      cart JSONB DEFAULT '[]'
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS products (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      price INT NOT NULL
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS orders (
      id SERIAL PRIMARY KEY,
      user_id INT REFERENCES users(id),
      items JSONB,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);

  const r = await pool.query('SELECT COUNT(*) FROM products');
  if (parseInt(r.rows[0].count) === 0) {
    await pool.query(`
      INSERT INTO products (name, price) VALUES
      ('Брелок S7avelii', 500),
      ('Футболка S7avelii', 1200),
      ('Кружка S7avelii', 800),
      ('Модель самолёта', 2500)
    `);
  }
}

initDB().catch(console.error);

// --- Auth ---
app.post('/api/register', async (req, res) => {
  try {
    const { fio, email, phone, password, dob, gender, cardNumber, cardType } = req.body;
    if (!fio || !email || !password) return res.status(400).json({ error: 'Missing fields' });

    const existing = await pool.query('SELECT id FROM users WHERE email=$1 OR phone=$2', [email, phone]);
    if (existing.rows.length) return res.status(400).json({ error: 'User exists' });

    const hash = await bcrypt.hash(password, 10);
    const r = await pool.query(
      `INSERT INTO users (fio,email,phone,password,dob,gender,card_number,card_type)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id,fio,email,phone,avatar`,
      [fio,email,phone || null,hash,dob || null,gender || null,cardNumber || null,cardType || null]
    );
    const user = r.rows[0];
    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Registration failed' }); }
});

app.post('/api/login', async (req,res)=>{
  try {
    const { identifier, password } = req.body;
    if (!identifier || !password) return res.status(400).json({ error:'Missing fields' });

    const r = await pool.query('SELECT * FROM users WHERE email=$1 OR phone=$1', [identifier]);
    const user = r.rows[0];
    if (!user) return res.status(400).json({ error:'User not found' });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(400).json({ error:'Wrong password' });

    delete user.password;
    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user });
  } catch(err) { console.error(err); res.status(500).json({ error:'Login failed' }); }
});

// --- Profile ---
app.get('/api/profile', auth, async (req,res)=>{
  try {
    const r = await pool.query('SELECT id,fio,email,phone,avatar,dob,gender,card_number,card_type,bonus_miles,status_miles,cart FROM users WHERE id=$1', [req.userId]);
    res.json({ user: r.rows[0] });
  } catch(err){ console.error(err); res.status(500).json({ error:'Profile failed' }); }
});

app.put('/api/profile', auth, async (req,res)=>{
  try {
    const allowed = ['fio','email','phone','dob','gender','card_number','card_type','bonus_miles','status_miles'];
    const sets = [];
    const vals = [];
    let i=1;
    for (let key of allowed) {
      if (req.body[key]!==undefined){ sets.push(`${key}=$${i++}`); vals.push(req.body[key]); }
    }
    if (!sets.length) return res.status(400).json({ error:'Nothing to update' });
    vals.push(req.userId);
    const q = `UPDATE users SET ${sets.join(', ')} WHERE id=$${i} RETURNING id,fio,email,phone,avatar,dob,gender,card_number,card_type,bonus_miles,status_miles,cart`;
    const r = await pool.query(q, vals);
    res.json({ user: r.rows[0] });
  } catch(err){ console.error(err); res.status(500).json({ error:'Update failed' }); }
});

// --- Avatar upload ---
const upload = multer({ dest: AVATAR_DIR });
app.post('/api/profile/avatar', auth, upload.single('avatar'), async (req,res)=>{
  try {
    if (!req.file) return res.status(400).json({ error:'No file' });
    const ext = path.extname(req.file.originalname) || '.jpg';
    const filename = `${req.userId}${ext}`;
    const target = path.join(AVATAR_DIR, filename);
    fs.renameSync(req.file.path, target);
    const avatarPath = `/avatars/${filename}`;
    await pool.query('UPDATE users SET avatar=$1 WHERE id=$2', [avatarPath, req.userId]);
    res.json({ avatar: avatarPath });
  } catch(err){ console.error(err); res.status(500).json({ error:'Avatar failed' }); }
});

// --- Products / Shop ---
app.get('/api/products', async (req,res)=>{
  const r = await pool.query('SELECT * FROM products ORDER BY id');
  res.json({ products: r.rows });
});

// --- Cart / Orders ---
app.get('/api/cart', auth, async (req,res)=>{
  const r = await pool.query('SELECT cart FROM users WHERE id=$1', [req.userId]);
  res.json(r.rows[0].cart || []);
});

app.post('/api/cart/add', auth, async (req,res)=>{
  const { id } = req.body;
  const prod = (await pool.query('SELECT id,name,price FROM products WHERE id=$1',[id])).rows[0];
  if(!prod) return res.status(404).json({ error:'Product not found' });
  const r = await pool.query('SELECT cart FROM users WHERE id=$1',[req.userId]);
  const cart = r.rows[0].cart || [];
  cart.push({...prod, qty:1});
  await pool.query('UPDATE users SET cart=$1 WHERE id=$2',[JSON.stringify(cart), req.userId]);
  res.json({ ok:true });
});

app.post('/api/checkout', auth, async (req,res)=>{
  const r = await pool.query('SELECT cart FROM users WHERE id=$1',[req.userId]);
  const cart = r.rows[0].cart || [];
  if(!cart.length) return res.status(400).json({ error:'Cart empty' });
  await pool.query('INSERT INTO orders (user_id,items) VALUES ($1,$2)', [req.userId, JSON.stringify(cart)]);
  await pool.query("UPDATE users SET cart='[]', bonus_miles = COALESCE(bonus_miles,0)+100 WHERE id=$1",[req.userId]);
  res.json({ ok:true });
});

// --- Start ---
app.listen(PORT, ()=>console.log(`✅ Server running on ${PORT}`));
