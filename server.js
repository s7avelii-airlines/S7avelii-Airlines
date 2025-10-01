// server.js
const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const IS_PROD = process.env.NODE_ENV === 'production';

const PUBLIC_DIR = path.join(__dirname, 'public');
const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');

app.use(express.json({ limit: '5mb' }));
app.use(cookieParser());
app.use(express.static(PUBLIC_DIR));

app.set('trust proxy', 1); // если используешь Render / прокси

app.use(session({
  name: 's7avelii.sid',
  secret: process.env.SESSION_SECRET || 'change_this_secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: IS_PROD,
    sameSite: 'lax',
    maxAge: 1000 * 60 * 60 * 24 * 14 // 14 дней
  }
}));

// Helper: ensure data dir + file
async function ensureUsersFile() {
  await fsp.mkdir(DATA_DIR, { recursive: true });
  try {
    await fsp.access(USERS_FILE, fs.constants.F_OK);
  } catch {
    await safeWriteFile(USERS_FILE, JSON.stringify([], null, 2));
  }
}

async function safeWriteFile(target, content) {
  const tmp = `${target}.tmp-${Date.now()}`;
  await fsp.writeFile(tmp, content, 'utf8');
  await fsp.rename(tmp, target);
}

async function loadUsers() {
  await ensureUsersFile();
  const raw = await fsp.readFile(USERS_FILE, 'utf8');
  try {
    return JSON.parse(raw || '[]');
  } catch (err) {
    console.error('users.json parse error, resetting file', err);
    await safeWriteFile(USERS_FILE, JSON.stringify([], null, 2));
    return [];
  }
}

async function saveUsers(users) {
  await ensureUsersFile();
  await safeWriteFile(USERS_FILE, JSON.stringify(users, null, 2));
}

// Utility to make safe user copy (no password)
function safeUser(u) {
  const copy = { ...u };
  delete copy.password;
  return copy;
}

/* ----------------------
   Authentication API
   ---------------------- */

// Register
app.post('/api/register', async (req, res) => {
  try {
    const { fio, phone, email = '', password, cardNumber = '', cardType = '', dob = '', gender = '' } = req.body;
    if (!fio || !phone || !password) {
      return res.status(400).json({ error: 'Поля fio, phone и password обязательны' });
    }

    const users = await loadUsers();
    if (email && users.find(u => u.email && u.email.toLowerCase() === email.toLowerCase())) {
      return res.status(400).json({ error: 'Пользователь с таким email уже зарегистрирован' });
    }
    if (users.find(u => u.phone === phone)) {
      return res.status(400).json({ error: 'Пользователь с таким телефоном уже зарегистрирован' });
    }

    const hashed = await bcrypt.hash(password, 10);
    const id = Date.now().toString(36) + Math.random().toString(36).slice(2, 8);

    const newUser = {
      id,
      fio,
      phone,
      email,
      password: hashed,
      cardNumber,
      cardType,
      dob,
      gender,
      avatar: '',
      bonusMiles: 0,
      cart: [], // корзина
      role: 'user',
      createdAt: new Date().toISOString()
    };

    users.push(newUser);
    await saveUsers(users);

    // set session
    req.session.userId = newUser.id;

    res.json({ ok: true, user: safeUser(newUser) });
  } catch (err) {
    console.error('register error', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { phone, email, password } = req.body;
    if ((!phone && !email) || !password) {
      return res.status(400).json({ error: 'Нужен phone или email и пароль' });
    }
    const users = await loadUsers();
    const user = users.find(u => (phone && u.phone === phone) || (email && u.email && u.email.toLowerCase() === email.toLowerCase()));
    if (!user) return res.status(400).json({ error: 'Пользователь не найден' });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(400).json({ error: 'Неверный пароль' });

    req.session.userId = user.id;
    res.json({ ok: true, user: safeUser(user) });
  } catch (err) {
    console.error('login error', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Logout
app.post('/api/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) console.warn('session destroy error', err);
    res.clearCookie('s7avelii.sid');
    res.json({ ok: true });
  });
});

/* ----------------------
   Profile
   ---------------------- */

app.get('/api/profile', async (req, res) => {
  try {
    if (!req.session.userId) return res.status(401).json({ error: 'Не авторизован' });
    const users = await loadUsers();
    const user = users.find(u => u.id === req.session.userId);
    if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
    res.json({ ok: true, user: safeUser(user) });
  } catch (err) {
    console.error('profile error', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// update profile (partial)
app.post('/api/update-profile', async (req, res) => {
  try {
    if (!req.session.userId) return res.status(401).json({ error: 'Не авторизован' });
    const users = await loadUsers();
    const idx = users.findIndex(u => u.id === req.session.userId);
    if (idx === -1) return res.status(404).json({ error: 'Пользователь не найден' });

    const allowed = ['fio','phone','email','cardNumber','cardType','dob','gender','avatar','bonusMiles','cart'];
    for (const k of allowed) {
      if (req.body[k] !== undefined) users[idx][k] = req.body[k];
    }

    await saveUsers(users);
    res.json({ ok: true, user: safeUser(users[idx]) });
  } catch (err) {
    console.error('profile update error', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/* ----------------------
   Cart endpoints
   ---------------------- */

// Add item to cart
// product = { id?: string, title, price, image, qty }
app.post('/api/cart/add', async (req, res) => {
  try {
    if (!req.session.userId) return res.status(401).json({ error: 'Не авторизован' });
    const product = req.body.product;
    if (!product || !product.title) return res.status(400).json({ error: 'Неверный товар' });

    const users = await loadUsers();
    const idx = users.findIndex(u => u.id === req.session.userId);
    if (idx === -1) return res.status(404).json({ error: 'Пользователь не найден' });

    // assign cartItemId for removal later
    const cartItemId = Date.now().toString(36) + Math.random().toString(36).slice(2,6);
    const item = { cartItemId, ...product, qty: product.qty || 1 };
    users[idx].cart = users[idx].cart || [];
    users[idx].cart.push(item);

    await saveUsers(users);
    res.json({ ok: true, cart: users[idx].cart });
  } catch (err) {
    console.error('cart add error', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get cart
app.get('/api/cart', async (req, res) => {
  try {
    if (!req.session.userId) return res.status(401).json({ error: 'Не авторизован' });
    const users = await loadUsers();
    const user = users.find(u => u.id === req.session.userId);
    if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
    res.json({ ok: true, cart: user.cart || [] });
  } catch (err) {
    console.error('cart get error', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Remove item from cart by cartItemId
app.post('/api/cart/remove', async (req, res) => {
  try {
    if (!req.session.userId) return res.status(401).json({ error: 'Не авторизован' });
    const { cartItemId } = req.body;
    if (!cartItemId) return res.status(400).json({ error: 'cartItemId required' });

    const users = await loadUsers();
    const idx = users.findIndex(u => u.id === req.session.userId);
    if (idx === -1) return res.status(404).json({ error: 'Пользователь не найден' });

    const before = users[idx].cart || [];
    const after = before.filter(i => i.cartItemId !== cartItemId);
    users[idx].cart = after;
    await saveUsers(users);
    res.json({ ok: true, cart: after });
  } catch (err) {
    console.error('cart remove error', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Clear cart
app.post('/api/cart/clear', async (req, res) => {
  try {
    if (!req.session.userId) return res.status(401).json({ error: 'Не авторизован' });
    const users = await loadUsers();
    const idx = users.findIndex(u => u.id === req.session.userId);
    if (idx === -1) return res.status(404).json({ error: 'Пользователь не найден' });
    users[idx].cart = [];
    await saveUsers(users);
    res.json({ ok: true, cart: [] });
  } catch (err) {
    console.error('cart clear error', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/* ----------------------
   Admin: list users (no passwords)
   ---------------------- */
app.get('/api/admin/users', async (req, res) => {
  try {
    // very simple admin gate: if logged in user role === 'admin'
    if (!req.session.userId) return res.status(401).json({ error: 'Не авторизован' });
    const users = await loadUsers();
    const me = users.find(u => u.id === req.session.userId);
    if (!me || me.role !== 'admin') return res.status(403).json({ error: 'Нет доступа' });

    const safe = users.map(u => {
      const c = { ...u };
      delete c.password;
      return c;
    });
    res.json({ ok: true, users: safe });
  } catch (err) {
    console.error('admin users error', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/* Fallback for SPA */
app.get('*', (req, res) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ error: 'API endpoint not found' });
  res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
});

(async () => {
  try {
    await ensureUsersFile();
    app.listen(PORT, () => {
      console.log(`Server listening on port ${PORT}`);
      console.log(`Public: ${PUBLIC_DIR}`);
      console.log(`Users file: ${USERS_FILE}`);
    });
  } catch (err) {
    console.error('Failed to start', err);
    process.exit(1);
  }
})();



