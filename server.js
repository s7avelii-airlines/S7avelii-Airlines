// server.js
const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');
const cors = require('cors');
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const PUBLIC_DIR = path.join(__dirname, 'public');

const IS_PROD = process.env.NODE_ENV === 'production';
const SESSION_SECRET = process.env.SESSION_SECRET || 'change-me-in-prod';

// middleware
app.use(express.json({ limit: '8mb' }));
app.use(cookieParser());
// CORS only if frontend may call from other origin — we allow credentials
app.use(cors({ origin: true, credentials: true }));
// serve static files
app.use(express.static(PUBLIC_DIR));

// sessions
app.use(session({
  name: 's7avelii.sid',
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: IS_PROD,
    sameSite: 'lax',
    maxAge: 1000 * 60 * 60 * 24 * 7 // 7 days
  }
}));

// helpers: ensure data dir and users file
async function ensureUsersFile() {
  await fsp.mkdir(DATA_DIR, { recursive: true });
  try {
    await fsp.access(USERS_FILE, fs.constants.F_OK);
  } catch (e) {
    await safeWriteFile(USERS_FILE, JSON.stringify([], null, 2));
  }
}

async function safeWriteFile(target, content) {
  const tmp = target + '.tmp-' + Date.now();
  await fsp.writeFile(tmp, content, 'utf8');
  await fsp.rename(tmp, target);
}

async function loadUsers() {
  await ensureUsersFile();
  const raw = await fsp.readFile(USERS_FILE, 'utf8');
  try {
    return JSON.parse(raw || '[]');
  } catch (e) {
    console.error('Invalid users.json, resetting', e);
    await safeWriteFile(USERS_FILE, JSON.stringify([], null, 2));
    return [];
  }
}

async function saveUsers(users) {
  await ensureUsersFile();
  await safeWriteFile(USERS_FILE, JSON.stringify(users, null, 2));
}

// utilities
function makeSafeUser(u) {
  const copy = { ...u };
  delete copy.password;
  return copy;
}

function newId() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2,8);
}

/* ---------------------------
   AUTH API
   --------------------------- */

// register
app.post('/api/register', async (req, res) => {
  try {
    const { fio, phone, email, password, cardNumber, cardType, dob, gender } = req.body;
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
    const id = newId();
    const user = {
      id,
      fio,
      phone,
      email: email || '',
      password: hashed,
      cardNumber: cardNumber || '',
      cardType: cardType || '',
      dob: dob || '',
      gender: gender || '',
      avatar: '',
      bonusMiles: 0,
      role: 'user',
      cart: [],      // cart stored per-user
      orders: [],    // user's orders
      createdAt: new Date().toISOString()
    };
    users.push(user);
    await saveUsers(users);

    // create session
    req.session.userId = user.id;

    const safe = makeSafeUser(user);
    res.json({ ok: true, user: safe });
  } catch (err) {
    console.error('register error', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// login (accept phone or email)
app.post('/api/login', async (req, res) => {
  try {
    const { phone, email, password } = req.body;
    if ((!phone && !email) || !password) return res.status(400).json({ error: 'Нужен phone или email и пароль' });

    const users = await loadUsers();
    const user = users.find(u => (phone && u.phone === phone) || (email && u.email && u.email.toLowerCase() === email.toLowerCase()));
    if (!user) return res.status(400).json({ error: 'Пользователь не найден' });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(400).json({ error: 'Неверный пароль' });

    req.session.userId = user.id;
    res.json({ ok: true, user: makeSafeUser(user) });
  } catch (err) {
    console.error('login error', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// logout
app.post('/api/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) console.warn('session destroy error', err);
    res.clearCookie('s7avelii.sid');
    res.json({ ok: true });
  });
});

/* ---------------------------
   PROFILE API
   --------------------------- */

app.get('/api/profile', async (req, res) => {
  try {
    if (!req.session.userId) return res.status(401).json({ error: 'Не авторизован' });
    const users = await loadUsers();
    const user = users.find(u => u.id === req.session.userId);
    if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
    res.json({ ok: true, user: makeSafeUser(user) });
  } catch (err) {
    console.error('profile error', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/profile/update', async (req, res) => {
  try {
    if (!req.session.userId) return res.status(401).json({ error: 'Не авторизован' });
    const users = await loadUsers();
    const user = users.find(u => u.id === req.session.userId);
    if (!user) return res.status(404).json({ error: 'Пользователь не найден' });

    const allowed = ['fio','phone','email','cardNumber','cardType','dob','gender','avatar','bonusMiles'];
    for (const k of allowed) {
      if (req.body[k] !== undefined) user[k] = req.body[k];
    }
    await saveUsers(users);
    res.json({ ok: true, user: makeSafeUser(user) });
  } catch (err) {
    console.error('profile update error', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// alias for legacy frontend
app.post('/api/update-profile', (req, res) => {
  // reuse previous route
  return app._router.handle(req, res, () => {}, '/api/profile/update', 'POST');
});

/* ---------------------------
   CART API (per-user)
   --------------------------- */

app.get('/api/cart', async (req, res) => {
  try {
    if (!req.session.userId) return res.status(401).json({ error: 'Не авторизован' });
    const users = await loadUsers();
    const user = users.find(u => u.id === req.session.userId);
    res.json({ ok: true, cart: (user && user.cart) ? user.cart : [] });
  } catch (err) {
    console.error('cart get error', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/cart/add', async (req, res) => {
  try {
    if (!req.session.userId) return res.status(401).json({ error: 'Не авторизован' });
    const item = req.body;
    if (!item || !item.id) return res.status(400).json({ error: 'Неверный товар' });

    const users = await loadUsers();
    const user = users.find(u => u.id === req.session.userId);
    if (!user) return res.status(404).json({ error: 'Пользователь не найден' });

    user.cart = user.cart || [];
    const existing = user.cart.find(x => x.id == item.id);
    if (existing) {
      existing.qty = (existing.qty || 1) + (item.qty || 1);
    } else {
      user.cart.push({
        id: item.id,
        title: item.title || '',
        price: item.price || '',
        image: item.image || '',
        qty: item.qty || 1
      });
    }
    await saveUsers(users);
    res.json({ ok: true, cart: user.cart });
  } catch (err) {
    console.error('cart add error', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/cart/remove', async (req, res) => {
  try {
    if (!req.session.userId) return res.status(401).json({ error: 'Не авторизован' });
    const { id, all } = req.body;
    if (!id) return res.status(400).json({ error: 'id required' });

    const users = await loadUsers();
    const user = users.find(u => u.id === req.session.userId);
    if (!user) return res.status(404).json({ error: 'Пользователь не найден' });

    user.cart = user.cart || [];
    const idx = user.cart.findIndex(x => x.id == id);
    if (idx === -1) return res.status(404).json({ error: 'Товар не найден в корзине' });

    if (all || (user.cart[idx].qty <= 1)) {
      user.cart.splice(idx, 1);
    } else {
      user.cart[idx].qty -= 1;
    }
    await saveUsers(users);
    res.json({ ok: true, cart: user.cart });
  } catch (err) {
    console.error('cart remove error', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/cart/clear', async (req, res) => {
  try {
    if (!req.session.userId) return res.status(401).json({ error: 'Не авторизован' });
    const users = await loadUsers();
    const user = users.find(u => u.id === req.session.userId);
    if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
    user.cart = [];
    await saveUsers(users);
    res.json({ ok: true });
  } catch (err) {
    console.error('cart clear error', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/cart/checkout', async (req, res) => {
  try {
    if (!req.session.userId) return res.status(401).json({ error: 'Не авторизован' });
    const users = await loadUsers();
    const user = users.find(u => u.id === req.session.userId);
    if (!user) return res.status(404).json({ error: 'Пользователь не найден' });

    const cart = user.cart || [];
    if (!cart.length) return res.status(400).json({ error: 'Корзина пуста' });

    const total = cart.reduce((s, it) => {
      // try to parse numbers from price strings (best effort)
      const digits = (it.price || '').replace(/[^\d,.-]/g, '').replace(',', '.');
      const n = parseFloat(digits) || 0;
      return s + n * (it.qty || 1);
    }, 0);

    const order = {
      id: newId(),
      items: cart,
      total,
      createdAt: new Date().toISOString(),
      status: 'pending'
    };
    user.orders = user.orders || [];
    user.orders.push(order);
    user.cart = [];
    await saveUsers(users);
    res.json({ ok: true, order });
  } catch (err) {
    console.error('checkout error', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/* ---------------------------
   Admin: list users (no passwords) - optional
   --------------------------- */
app.get('/api/admin/users', async (req, res) => {
  // Basic admin by role in session
  try {
    if (!req.session.userId) return res.status(401).json({ error: 'Не авторизован' });
    const users = await loadUsers();
    const me = users.find(u => u.id === req.session.userId);
    if (!me || me.role !== 'admin') return res.status(403).json({ error: 'Нет доступа' });
    const safe = users.map(u => {
      const c = { ...u }; delete c.password; return c;
    });
    res.json({ ok: true, users: safe });
  } catch (err) {
    console.error('admin users error', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/* ---------------------------
   SPA fallback: serve index.html for non-API paths
   --------------------------- */
app.get('*', (req, res) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ error: 'API endpoint not found' });
  const index = path.join(PUBLIC_DIR, 'index.html');
  if (fs.existsSync(index)) return res.sendFile(index);
  return res.send('S7avelii server');
});

/* ---------------------------
   start
   --------------------------- */
(async () => {
  try {
    await ensureUsersFile();
    app.listen(PORT, () => {
      console.log(`Server listening on port ${PORT}`);
      console.log(`Public folder: ${PUBLIC_DIR}`);
      console.log(`Users file: ${USERS_FILE}`);
    });
  } catch (err) {
    console.error('Failed to start', err);
    process.exit(1);
  }
})();
