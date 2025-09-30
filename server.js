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

// --- paths ---
const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const PUBLIC_DIR = path.join(__dirname, 'public');

// --- middlewares ---
app.use(express.json({ limit: '5mb' }));
app.use(cookieParser());

// === CORS для фронтенда ===
app.use(cors({
  origin: "https://s7avelii.onrender.com", // замените на ваш домен фронта
  credentials: true
}));

// serve static files (index.html, css, js)
app.use(express.static(PUBLIC_DIR));

// session configuration
const IS_PROD = process.env.NODE_ENV === 'production';
app.use(session({
  name: 's7avelii.sid',
  secret: process.env.SESSION_SECRET || 'please-change-this-to-a-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: IS_PROD,  // true если HTTPS
    sameSite: 'lax',
    maxAge: 1000 * 60 * 60 * 24 * 7 // 7 дней
  }
}));

// === helper: ensure data dir + file exists ===
async function ensureUsersFile() {
  try {
    await fsp.mkdir(DATA_DIR, { recursive: true });
    try { await fsp.access(USERS_FILE, fs.constants.F_OK); }
    catch(e) { await safeWriteFile(USERS_FILE, JSON.stringify([], null, 2)); }
  } catch (err) {
    console.error('Cannot ensure data dir/file:', err);
    throw err;
  }
}

async function safeWriteFile(targetPath, content) {
  const tmp = targetPath + '.tmp-' + Date.now();
  await fsp.writeFile(tmp, content, 'utf8');
  await fsp.rename(tmp, targetPath);
}

async function loadUsers() {
  await ensureUsersFile();
  const raw = await fsp.readFile(USERS_FILE, 'utf8');
  try { return JSON.parse(raw || '[]'); }
  catch(e) { 
    console.error('Invalid users.json — resetting to []', e);
    await safeWriteFile(USERS_FILE, JSON.stringify([], null, 2));
    return [];
  }
}

async function saveUsers(users) {
  await ensureUsersFile();
  await safeWriteFile(USERS_FILE, JSON.stringify(users, null, 2));
}

// === API ===

// register
app.post('/api/register', async (req, res) => {
  try {
    const { fio, phone, email, dob, gender, card, cardType } = req.body;
    if (!fio || !phone) return res.status(400).json({ error: 'ФИО и телефон обязательны' });

    const users = await loadUsers();

    if (email && users.find(u => u.email?.toLowerCase() === email.toLowerCase()))
      return res.status(400).json({ error: 'Email уже зарегистрирован' });
    if (users.find(u => u.phone === phone))
      return res.status(400).json({ error: 'Телефон уже зарегистрирован' });

    const id = Date.now().toString(36) + Math.random().toString(36).slice(2,8);
    const newUser = { id, fio, phone, email: email||'', dob: dob||'', gender: gender||'', card, cardType, createdAt: new Date().toISOString() };

    users.push(newUser);
    await saveUsers(users);

    req.session.userId = newUser.id;
    res.json({ ok: true, user: newUser });
  } catch(err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// login
app.post('/api/login', async (req, res) => {
  try {
    const { phone, email } = req.body;
    if (!phone && !email) return res.status(400).json({ error: 'Нужен phone или email' });

    const users = await loadUsers();
    const user = users.find(u => (phone && u.phone===phone) || (email && u.email?.toLowerCase()===email.toLowerCase()));
    if (!user) return res.status(400).json({ error: 'Пользователь не найден' });

    req.session.userId = user.id;
    res.json({ ok: true, user });
  } catch(err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// profile
app.get('/api/profile', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Не авторизован' });
  const users = await loadUsers();
  const user = users.find(u => u.id === req.session.userId);
  if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
  res.json({ ok: true, user });
});

// logout
app.post('/api/logout', (req,res) => {
  req.session.destroy(err => {
    if(err) console.warn(err);
    res.clearCookie('s7avelii.sid');
    res.json({ ok:true });
  });
});

// fallback SPA
app.get('*', (req,res) => {
  if(req.path.startsWith('/api/')) return res.status(404).json({ error:'API not found' });
  res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
});

// start
(async()=>{
  try {
    await ensureUsersFile();
    app.listen(PORT, ()=>console.log(`Server listening on port ${PORT}`));
  } catch(err) {
    console.error('Failed to start', err);
  }
})();
