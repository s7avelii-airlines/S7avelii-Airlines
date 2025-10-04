// server.js
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const DOMAIN = 'https://www.s7avelii-airlines.ru';

const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const PUBLIC_DIR = path.join(__dirname, 'public');

// --- Middleware ---
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(PUBLIC_DIR));

app.use(session({
  name: 's7avelii.sid',
  secret: process.env.SESSION_SECRET || 's7avelii-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: false, // если HTTPS включен, поменяй на true
    sameSite: 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
}));

// --- Helpers ---
async function ensureFiles() {
  await fsp.mkdir(DATA_DIR, { recursive: true });
  try { await fsp.access(USERS_FILE); } catch {
    await fsp.writeFile(USERS_FILE, '[]', 'utf8');
  }
}

async function loadUsers() {
  await ensureFiles();
  const raw = await fsp.readFile(USERS_FILE, 'utf8');
  return JSON.parse(raw || '[]');
}

async function saveUsers(users) {
  await fsp.writeFile(USERS_FILE, JSON.stringify(users, null, 2), 'utf8');
}

function makeId() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
}

function withoutPassword(u) {
  const c = { ...u };
  delete c.password;
  return c;
}

// --- Auth ---
app.post('/api/register', async (req, res) => {
  const { fio, dob, gender, email, phone, password, cardNumber, cardType } = req.body;

  if (!fio || !email || !phone || !password)
    return res.status(400).json({ error: 'Заполните все обязательные поля.' });

  const users = await loadUsers();
  if (users.find(u => u.email === email))
    return res.status(400).json({ error: 'Email уже зарегистрирован.' });
  if (users.find(u => u.phone === phone))
    return res.status(400).json({ error: 'Телефон уже зарегистрирован.' });

  const hash = await bcrypt.hash(password, 10);
  const newUser = {
    id: makeId(),
    fio, dob, gender, email, phone,
    password: hash,
    cardNumber: cardNumber || '',
    cardType: cardType || '',
    bonusMiles: 0,
    cart: [],
    orders: [],
    createdAt: new Date().toISOString()
  };

  users.push(newUser);
  await saveUsers(users);

  req.session.userId = newUser.id;
  res.json({ ok: true, user: withoutPassword(newUser) });
});

app.post('/api/login', async (req, res) => {
  const { phone, email, password } = req.body;
  if ((!phone && !email) || !password)
    return res.status(400).json({ error: 'Введите телефон/email и пароль' });

  const users = await loadUsers();
  const user = users.find(u => u.phone === phone || u.email === email);
  if (!user) return res.status(400).json({ error: 'П
  if (!user) return res.status(400).json({ error: 'Пользователь не найден' });
  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(400).json({ error: 'Неверный пароль' });

  req.session.userId = user.id;
  res.json({ ok: true, user: withoutPassword(user) });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('s7avelii.sid');
    res.json({ ok: true });
  });
});

app.get('/api/profile', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Не авторизован' });
  const users = await loadUsers();
  const user = users.find(u => u.id === req.session.userId);
  if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
  res.json({ ok: true, user: withoutPassword(user) });
});

// --- Корзина и заказы ---
app.post('/api/cart/add', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Не авторизован' });
  const users = await loadUsers();
  const user = users.find(u => u.id === req.session.userId);
  if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
  user.cart.push({ ...req.body, id: makeId(), addedAt: new Date().toISOString() });
  await saveUsers(users);
  res.json({ ok: true, cart: user.cart });
});

app.post('/api/cart/checkout', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Не авторизован' });
  const users = await loadUsers();
  const user = users.find(u => u.id === req.session.userId);
  if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
  if (!user.cart.length) return res.status(400).json({ error: 'Корзина пуста' });

  const total = user.cart.reduce((sum, item) => sum + (parseFloat(item.price) || 0), 0);
  const order = { id: makeId(), createdAt: new Date().toISOString(), items: user.cart, total };
  user.orders.push(order);
  user.cart = [];
  await saveUsers(users);
  res.json({ ok: true, order });
});

// fallback
app.get('*', (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
});

// старт
(async () => {
  await ensureFiles();
  app.listen(PORT, () => console.log(`✅ Сервер запущен на ${DOMAIN}:${PORT}`));
})();
