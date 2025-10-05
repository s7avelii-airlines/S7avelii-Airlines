// server.js
const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// PostgreSQL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Middleware
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

app.use(session({
  name: 's7avelii.sid',
  secret: process.env.SESSION_SECRET || 'please-change-this-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 1000 * 60 * 60 * 24 * 7
  }
}));

// ---------- Helpers ----------
function withoutPassword(u) {
  const copy = { ...u };
  delete copy.password;
  return copy;
}

// ---------- Auth & User API ----------

// Register
app.post('/api/register', async (req, res) => {
  try {
    const { fio, phone, email, password, cardNumber, cardType, dob, gender } = req.body;
    if (!fio || !phone || !password) return res.status(400).json({ error: 'fio, phone, password обязательны' });

    const client = await pool.connect();
    try {
      const existing = await client.query(
        'SELECT id FROM users WHERE phone=$1 OR (email=$2 AND $2 IS NOT NULL)',
        [phone, email]
      );
      if (existing.rows.length) return res.status(400).json({ error: 'Пользователь уже существует' });

      const hashed = await bcrypt.hash(password, 10);
      const result = await client.query(
        `INSERT INTO users (fio, phone, email, password, card_number, card_type, dob, gender, avatar, bonus_miles, role, cart, created_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'',0,'user','[]',NOW())
         RETURNING *`,
        [fio, phone, email || '', hashed, cardNumber || '', cardType || '', dob || '', gender || '']
      );

      const newUser = result.rows[0];
      req.session.userId = newUser.id;
      res.json({ ok: true, user: withoutPassword(newUser) });
    } finally {
      client.release();
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { phone, email, password } = req.body;
    if ((!phone && !email) || !password) return res.status(400).json({ error: 'phone/email и password обязательны' });

    const client = await pool.connect();
    try {
      const result = await client.query(
        'SELECT * FROM users WHERE phone=$1 OR (email=$2 AND $2 IS NOT NULL)',
        [phone, email]
      );
      const user = result.rows[0];
      if (!user) return res.status(400).json({ error: 'Пользователь не найден' });

      const ok = await bcrypt.compare(password, user.password);
      if (!ok) return res.status(400).json({ error: 'Неверный пароль' });

      req.session.userId = user.id;
      res.json({ ok: true, user: withoutPassword(user) });
    } finally {
      client.release();
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
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

// Get current profile
app.get('/api/profile', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Не авторизован' });
  const client = await pool.connect();
  try {
    const result = await client.query('SELECT * FROM users WHERE id=$1', [req.session.userId]);
    const user = result.rows[0];
    if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
    res.json({ ok: true, user: withoutPassword(user) });
  } finally {
    client.release();
  }
});

// Update profile
app.post(['/api/update-profile','/api/profile/update'], async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Не авторизован' });
  const fields = ['fio','phone','email','card_number','card_type','dob','gender','avatar','bonus_miles','password','vk','telegram'];
  const updates = [];
  const values = [];
  fields.forEach(f=>{
    if(req.body[f] !== undefined) {
      updates.push(`${f}=$${updates.length+1}`);
      values.push(req.body[f]);
    }
  });
  if (updates.length === 0) return res.status(400).json({ error: 'Нет полей для обновления' });
  values.push(req.session.userId);

  const client = await pool.connect();
  try {
    if (req.body.password) {
      const hashed = await bcrypt.hash(req.body.password, 10);
      const idx = fields.indexOf('password');
      values[idx] = hashed;
    }
    const result = await client.query(
      `UPDATE users SET ${updates.join(', ')} WHERE id=$${values.length} RETURNING *`,
      values
    );
    const user = result.rows[0];
    res.json({ ok: true, user: withoutPassword(user) });
  } finally {
    client.release();
  }
});

// Cart API
app.post('/api/cart/add', async (req,res)=>{
  if(!req.session.userId) return res.status(401).json({error:'Не авторизован'});
  const client = await pool.connect();
  try {
    const result = await client.query('SELECT cart FROM users WHERE id=$1', [req.session.userId]);
    const user = result.rows[0];
    const cart = user.cart || [];
    cart.push({ id: Date.now().toString(36), added_at: new Date(), ...req.body });
    await client.query('UPDATE users SET cart=$1 WHERE id=$2', [cart, req.session.userId]);
    res.json({ok:true, cart});
  } finally { client.release(); }
});

app.get('/api/cart', async (req,res)=>{
  if(!req.session.userId) return res.status(401).json({error:'Не авторизован'});
  const client = await pool.connect();
  try {
    const result = await client.query('SELECT cart FROM users WHERE id=$1', [req.session.userId]);
    res.json({ok:true, cart: result.rows[0].cart || []});
  } finally { client.release(); }
});

app.delete('/api/cart/:itemId', async (req,res)=>{
  if(!req.session.userId) return res.status(401).json({error:'Не авторизован'});
  const { itemId } = req.params;
  const client = await pool.connect();
  try {
    const result = await client.query('SELECT cart FROM users WHERE id=$1', [req.session.userId]);
    let cart = result.rows[0].cart || [];
    cart = cart.filter(i => String(i.id)!==String(itemId));
    await client.query('UPDATE users SET cart=$1 WHERE id=$2', [cart, req.session.userId]);
    res.json({ok:true, cart});
  } finally { client.release(); }
});

app.post('/api/cart/clear', async (req,res)=>{
  if(!req.session.userId) return res.status(401).json({error:'Не авторизован'});
  const client = await pool.connect();
  try {
    await client.query('UPDATE users SET cart=$1 WHERE id=$2', [[], req.session.userId]);
    res.json({ok:true, cart:[]});
  } finally { client.release(); }
});

// SPA fallback
const path = require('path');
app.use(express.static(path.join(__dirname,'public')));
app.get('*', (req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));

// Start
app.listen(PORT, ()=>console.log(`Server running on port ${PORT}`));
