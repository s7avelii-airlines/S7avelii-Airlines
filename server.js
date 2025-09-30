// server.js
const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

// paths
const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const PUBLIC_DIR = path.join(__dirname, 'public');

// middleware
app.use(express.json({ limit: '5mb' }));
app.use(cookieParser());

// CORS: если фронтенд будет на другом домене — укажи в ALLOWED_ORIGINS
const ALLOWED_ORIGINS = [
  process.env.PUBLIC_ORIGIN || 'https://s7avelii.onrender.com',
  'http://localhost:3000'
];
app.use(cors({
  origin: function(origin, cb){
    // allow requests with no origin (like mobile apps or curl)
    if(!origin) return cb(null, true);
    if(ALLOWED_ORIGINS.indexOf(origin) !== -1) return cb(null, true);
    return cb(null, false);
  },
  credentials: true
}));

// serve static files
app.use(express.static(PUBLIC_DIR));

const IS_PROD = process.env.NODE_ENV === 'production' || !!process.env.RENDER;
app.use(session({
  name: 's7avelii.sid',
  secret: process.env.SESSION_SECRET || 'please-change-this-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: IS_PROD,      // true on Render (HTTPS)
    sameSite: 'lax',
    maxAge: 1000 * 60 * 60 * 24 * 7 // 7 days
  }
}));

// helper: ensure data dir + users file
async function ensureUsersFile(){
  await fsp.mkdir(DATA_DIR, { recursive: true });
  try { await fsp.access(USERS_FILE); }
  catch { await fsp.writeFile(USERS_FILE, '[]', 'utf8'); }
}

async function loadUsers(){
  await ensureUsersFile();
  const raw = await fsp.readFile(USERS_FILE, 'utf8');
  try { return JSON.parse(raw || '[]'); }
  catch {
    await fsp.writeFile(USERS_FILE, '[]', 'utf8');
    return [];
  }
}

async function saveUsers(users){
  await ensureUsersFile();
  await fsp.writeFile(USERS_FILE, JSON.stringify(users, null, 2), 'utf8');
}

// ---------- API ----------

// register
// expects: { fio, phone, email, dob, gender, card, cardType, password }
app.post('/api/register', async (req, res) => {
  try {
    const { fio, phone, email, dob, gender, card, cardType, password } = req.body;
    if(!fio || !phone || !password) return res.status(400).json({ error: 'ФИО, телефон и пароль обязательны' });

    const users = await loadUsers();
    if(email && users.find(u => u.email && u.email.toLowerCase() === email.toLowerCase())){
      return res.status(400).json({ error: 'Пользователь с таким email уже зарегистрирован' });
    }
    if(users.find(u => u.phone === phone)){
      return res.status(400).json({ error: 'Пользователь с таким телефоном уже зарегистрирован' });
    }

    const hashed = await bcrypt.hash(password, 10);
    const id = Date.now().toString(36) + Math.random().toString(36).slice(2,8);

    const newUser = {
      id,
      fio,
      phone,
      email: email || '',
      password: hashed,
      cardNumber: card || '',
      cardType: cardType || '',
      dob: dob || '',
      gender: gender || '',
      avatar: '',
      bonusMiles: 0,
      role: 'user',
      createdAt: new Date().toISOString()
    };

    users.push(newUser);
    await saveUsers(users);

    req.session.userId = newUser.id;
    const safe = { ...newUser }; delete safe.password;
    return res.json({ ok: true, user: safe });
  } catch (err) {
    console.error('register error', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// login
// expects: { phone OR email, password }
app.post('/api/login', async (req, res) => {
  try {
    const { phone, email, password } = req.body;
    if((!phone && !email) || !password) return res.status(400).json({ error: 'Нужен phone/email и пароль' });

    const users = await loadUsers();
    const user = users.find(u => (phone && u.phone === phone) || (email && u.email && u.email.toLowerCase() === email.toLowerCase()));
    if(!user) return res.status(400).json({ error: 'Пользователь не найден' });

    const ok = await bcrypt.compare(password, user.password);
    if(!ok) return res.status(400).json({ error: 'Неверный пароль' });

    req.session.userId = user.id;
    const safe = { ...user }; delete safe.password;
    return res.json({ ok: true, user: safe });
  } catch (err) {
    console.error('login error', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// profile (requires session)
app.get('/api/profile', async (req, res) => {
  try {
    if(!req.session.userId) return res.status(401).json({ error: 'Не авторизован' });
    const users = await loadUsers();
    const user = users.find(u => u.id === req.session.userId);
    if(!user) return res.status(404).json({ error: 'Пользователь не найден' });
    const safe = { ...user }; delete safe.password;
    return res.json({ ok: true, user: safe });
  } catch (err) {
    console.error('profile error', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// logout
app.post('/api/logout', (req, res) => {
  req.session.destroy(err => {
    if(err) console.warn('session destroy error', err);
    res.clearCookie('s7avelii.sid');
    res.json({ ok: true });
  });
});

// admin: list users (no password) — role must be 'admin'
app.get('/api/admin/users', async (req, res) => {
  try {
    if(!req.session.userId) return res.status(401).json({ error: 'Не авторизован' });
    const users = await loadUsers();
    const me = users.find(u => u.id === req.session.userId);
    if(!me || me.role !== 'admin') return res.status(403).json({ error: 'Нет доступа' });
    const safeList = users.map(u => { const c = {...u}; delete c.password; return c; });
    return res.json({ ok: true, users: safeList });
  } catch (err) {
    console.error('admin users error', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// SPA fallback (serve index.html)
app.get('*', (req, res) => {
  if(req.path.startsWith('/api/')) return res.status(404).json({ error: 'API not found' });
  res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
});

// start
(async () => {
  try {
    await ensureUsersFile();
    app.listen(PORT, () => console.log(`Server listening on port ${PORT}`));
  } catch (err) {
    console.error('Failed to start', err);
    process.exit(1);
  }
})();
