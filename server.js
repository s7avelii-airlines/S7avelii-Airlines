const express = require('express');
const session = require('express-session');
const fs = require('fs').promises;
const path = require('path');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = 3000;

const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');

app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  name: 's7avelii.sid',
  secret: 'supersecretkey',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, maxAge: 1000 * 60 * 60 * 24 * 7 } // 7 дней
}));

async function ensureFiles() {
  await fs.mkdir(DATA_DIR, { recursive: true });
  try {
    await fs.access(USERS_FILE);
  } catch {
    await fs.writeFile(USERS_FILE, JSON.stringify([]));
  }
}

async function loadUsers() {
  await ensureFiles();
  const raw = await fs.readFile(USERS_FILE, 'utf8');
  return JSON.parse(raw || '[]');
}

async function saveUsers(users) {
  await fs.writeFile(USERS_FILE, JSON.stringify(users, null, 2));
}

function withoutPassword(u) {
  const copy = { ...u };
  delete copy.password;
  return copy;
}

// Registration
app.post('/api/register', async (req, res) => {
  const { fio, email, phone, password } = req.body;
  if (!fio || !password || (!email && !phone)) return res.status(400).json({ error: 'Нужны fio, пароль и email или телефон' });

  const users = await loadUsers();
  if (email && users.find(u => u.email === email)) return res.status(400).json({ error: 'Пользователь с таким email уже существует' });
  if (phone && users.find(u => u.phone === phone)) return res.status(400).json({ error: 'Пользователь с таким телефоном уже существует' });

  const hashed = await bcrypt.hash(password, 10);
  const newUser = {
    id: Date.now().toString(),
    fio,
    email: email || '',
    phone: phone || '',
    password: hashed,
    dob: '', gender: '', cardNumber: '', cardType: '',
    bonusMiles: 0, orders: [], cart: []
  };
  users.push(newUser);
  await saveUsers(users);
  req.session.userId = newUser.id;

  res.json({ ok: true, user: withoutPassword(newUser) });
});

// Login
app.post('/api/login', async (req, res) => {
  const { email, phone, password } = req.body;
  if (!password || (!email && !phone)) return res.status(400).json({ error: 'Нужны пароль и email или телефон' });

  const users = await loadUsers();
  const user = users.find(u => (email && u.email === email) || (phone && u.phone === phone));
  if (!user) return res.status(400).json({ error: 'Пользователь не найден' });

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(400).json({ error: 'Неверный пароль' });

  req.session.userId = user.id;
  res.json({ ok: true, user: withoutPassword(user) });
});

// Logout
app.post('/api/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) console.error(err);
    res.clearCookie('s7avelii.sid');
    res.json({ ok: true });
  });
});

// Get profile
app.get('/api/profile', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Не авторизован' });
  const users = await loadUsers();
  const user = users.find(u => u.id === req.session.userId);
  if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
  res.json({ ok: true, user: withoutPassword(user) });
});

app.listen(PORT, async () => {
  await ensureFiles();
  console.log(`Server running on http://localhost:${PORT}`);
});
