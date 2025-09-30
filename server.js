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
app.use(cors({ origin: true, credentials: true }));
app.use(express.static(PUBLIC_DIR));

const IS_PROD = true; // на Render всегда production
app.use(session({
  name: 's7avelii.sid',
  secret: process.env.SESSION_SECRET || 'please-change-this',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: IS_PROD,
    sameSite: 'lax',
    maxAge: 1000 * 60 * 60 * 24 * 7 // 7 дней
  }
}));

// --- ensure users file ---
async function ensureUsersFile() {
  await fsp.mkdir(DATA_DIR, { recursive: true });
  try {
    await fsp.access(USERS_FILE);
  } catch {
    await fsp.writeFile(USERS_FILE, '[]', 'utf8');
  }
}

async function loadUsers() {
  await ensureUsersFile();
  const raw = await fsp.readFile(USERS_FILE, 'utf8');
  try { return JSON.parse(raw || '[]'); }
  catch { return []; }
}

async function saveUsers(users) {
  await ensureUsersFile();
  await fsp.writeFile(USERS_FILE, JSON.stringify(users, null, 2), 'utf8');
}

// --- API ---
// register
app.post('/api/register', async (req, res) => {
  const { fio, phone, email, dob, gender, card, cardType } = req.body;
  if (!fio || !phone) return res.status(400).json({ error: 'ФИО и телефон обязательны' });

  const users = await loadUsers();
  if (email && users.find(u => u.email?.toLowerCase() === email.toLowerCase()))
    return res.status(400).json({ error: 'Email уже зарегистрирован' });
  if (users.find(u => u.phone === phone))
    return res.status(400).json({ error: 'Телефон уже зарегистрирован' });

  const password = Math.random().toString(36).slice(2,10); // временный пароль
  const hashed = await bcrypt.hash(password, 10);
  const id = Date.now().toString(36) + Math.random().toString(36).slice(2,8);

  const newUser = { id, fio, phone, email: email||'', dob: dob||'', gender: gender||'', card, cardType, password, createdAt: new Date().toISOString() };
  users.push(newUser);
  await saveUsers(users);

  req.session.userId = newUser.id;
  const safe = { ...newUser }; delete safe.password;
  res.json({ ok: true, user: safe });
});

// login
app.post('/api/login', async (req, res) => {
  const { phone, email } = req.body;
  if (!phone && !email) return res.status(400).json({ error: 'Phone или Email обязателен' });

  const users = await loadUsers();
  const user = users.find(u => (phone && u.phone === phone) || (email && u.email?.toLowerCase() === email.toLowerCase()));
  if (!user) return res.status(400).json({ error: 'Пользователь не найден' });

  req.session.userId = user.id;
  const safe = { ...user }; delete safe.password;
  res.json({ ok: true, user: safe });
});

// profile
app.get('/api/profile', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Не авторизован' });
  const users = await loadUsers();
  const user = users.find(u => u.id === req.session.userId);
  if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
  const safe = { ...user }; delete safe.password;
  res.json({ ok: true, user: safe });
});

// logout
app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

// fallback для SPA
app.get('*', (req, res) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ error: 'API не найден' });
  res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
});

// start server
(async () => {
  try {
    await ensureUsersFile();
    app.listen(PORT, () => console.log(`Server on port ${PORT}`));
  } catch(err) {
    console.error('Failed to start server', err);
    process.exit(1);
  }
})();
