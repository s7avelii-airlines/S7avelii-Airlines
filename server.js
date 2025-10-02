// server.js
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const fs = require('fs').promises;
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const PUBLIC_DIR = path.join(__dirname, 'public');

app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: false }));
app.use(express.static(PUBLIC_DIR));

// Сессии
app.use(session({
  name: 'myapp.sid',
  secret: process.env.SESSION_SECRET || 'change_this_secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    maxAge: 1000 * 60 * 60 * 24 * 30 // 30 дней
  }
}));

// --- Работа с файлами ---
async function ensureFiles() {
  await fs.mkdir(DATA_DIR, { recursive: true });
  try {
    await fs.access(USERS_FILE);
  } catch {
    await fs.writeFile(USERS_FILE, JSON.stringify([], null, 2));
  }
}

async function loadUsers() {
  await ensureFiles();
  const raw = await fs.readFile(USERS_FILE, 'utf8');
  try {
    return JSON.parse(raw || '[]');
  } catch {
    return [];
  }
}

async function saveUsers(users) {
  await fs.writeFile(USERS_FILE, JSON.stringify(users, null, 2));
}

function withoutPassword(user) {
  const { password, ...rest } = user;
  return rest;
}

// --- Регистрация ---
app.post('/api/register', async (req, res) => {
  const { fio, phone, password } = req.body;
  if (!fio || !phone || !password) return res.status(400).json({ error: 'fio, phone, password обязательны' });

  const users = await loadUsers();
  if (users.find(u => u.phone === phone)) return res.status(400).json({ error: 'Пользователь уже существует' });

  const hashed = await bcrypt.hash(password, 10);
  const newUser = {
    id: Date.now().toString(),
    fio,
    phone,
    password: hashed,
    cart: [],
    createdAt: new Date().toISOString()
  };
  users.push(newUser);
  await saveUsers(users);

  req.session.userId = newUser.id; // создаём сессию
  res.json({ ok: true, user: withoutPassword(newUser) });
});

// --- Логин ---
app.post('/api/login', async (req, res) => {
  const { phone, password } = req.body;
  if (!phone || !password) return res.status(400).json({ error: 'phone и password обязательны' });

  const users = await loadUsers();
  const user = users.find(u => u.phone === phone);
  if (!user) return res.status(400).json({ error: 'Пользователь не найден' });

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(400).json({ error: 'Неверный пароль' });

  req.session.userId = user.id;
  res.json({ ok: true, user: withoutPassword(user) });
});

// --- Получить профиль (авторизация по сессии) ---
app.get('/api/profile', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Не авторизован' });
  const users = await loadUsers();
  const user = users.find(u => u.id === req.session.userId);
  if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
  res.json({ ok: true, user: withoutPassword(user) });
});

// --- Выход ---
app.post('/api/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) console.warn(err);
    res.clearCookie('myapp.sid');
    res.json({ ok: true });
  });
});

// --- Корзина ---
app.post('/api/cart/add', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Не авторизован' });
  const item = req.body;

  const users = await loadUsers();
  const user = users.find(u => u.id === req.session.userId);
  user.cart.push({ ...item, id: Date.now().toString() });

  await saveUsers(users);
  res.json({ ok: true, cart: user.cart });
});

app.get('/api/cart', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Не авторизован' });
  const users = await loadUsers();
  const user = users.find(u => u.id === req.session.userId);
  res.json({ ok: true, cart: user.cart });
});

// --- SPA fallback ---
app.get('*', (req, res) => {
  const indexFile = path.join(PUBLIC_DIR, 'index.html');
  res.sendFile(indexFile);
});

// --- Старт сервера ---
app.listen(PORT, () => console.log(`Server started on http://localhost:${PORT}`));
