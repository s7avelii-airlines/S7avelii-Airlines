// server.js
// Lightweight file-backed server for S7avelii — users + cart + orders
// Uses pure-JS bcrypt (bcryptjs) to avoid native build issues on deploy platforms.

const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const IS_PROD = process.env.NODE_ENV === 'production';

const PUBLIC_DIR = path.join(__dirname, 'public');
const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const CARTS_FILE = path.join(DATA_DIR, 'carts.json');
const ORDERS_FILE = path.join(DATA_DIR, 'orders.json');

// middlewares
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(PUBLIC_DIR));

// session
app.use(session({
  name: 's7avelii.sid',
  secret: process.env.SESSION_SECRET || 'please-change-this-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: IS_PROD, // ensure https in prod
    sameSite: 'lax',
    maxAge: 1000 * 60 * 60 * 24 * 7 // 7 days
  }
}));

// Safe write helper (atomic-ish)
async function safeWriteFile(filePath, content) {
  const tmp = filePath + '.tmp-' + Date.now();
  await fsp.writeFile(tmp, content, { encoding: 'utf8' });
  await fsp.rename(tmp, filePath);
}

// Ensure data files exist
async function ensureDataFiles() {
  await fsp.mkdir(DATA_DIR, { recursive: true });
  async function ensure(fp, initial) {
    try {
      await fsp.access(fp, fs.constants.F_OK);
    } catch (e) {
      await safeWriteFile(fp, JSON.stringify(initial, null, 2));
    }
  }
  await ensure(USERS_FILE, []);
  await ensure(CARTS_FILE, {});
  await ensure(ORDERS_FILE, []);
}

async function loadJson(fp, fallback) {
  try {
    const raw = await fsp.readFile(fp, 'utf8');
    return JSON.parse(raw || JSON.stringify(fallback));
  } catch (e) {
    console.error('Failed to load JSON', fp, e);
    return fallback;
  }
}
async function saveJson(fp, data) {
  await safeWriteFile(fp, JSON.stringify(data, null, 2));
}

// Users helpers
async function loadUsers() { return loadJson(USERS_FILE, []); }
async function saveUsers(u){ return saveJson(USERS_FILE, u); }

// Carts helpers (object: { userId: [items...] })
async function loadCarts(){ return loadJson(CARTS_FILE, {}); }
async function saveCarts(c){ return saveJson(CARTS_FILE, c); }

// Orders helpers
async function loadOrders(){ return loadJson(ORDERS_FILE, []); }
async function saveOrders(o){ return saveJson(ORDERS_FILE, o); }

/* ----------------- Authentication API ----------------- */

// register
app.post('/api/register', async (req, res) => {
  try {
    const { fio, phone, email, password, cardNumber, cardType, dob, gender } = req.body;
    if (!fio || !phone || !password) return res.status(400).json({ error: 'Поля fio, phone и password обязательны' });

    const users = await loadUsers();
    if (email && users.find(u => u.email && u.email.toLowerCase() === String(email).toLowerCase())) {
      return res.status(400).json({ error: 'Пользователь с таким email уже зарегистрирован' });
    }
    if (users.find(u => u.phone === phone)) {
      return res.status(400).json({ error: 'Пользователь с таким телефоном уже зарегистрирован' });
    }

    const hashed = await bcrypt.hash(password, 10);
    const id = Date.now().toString(36) + Math.random().toString(36).slice(2,8);
    const newUser = {
      id, fio, phone, email: email||'', password: hashed,
      cardNumber: cardNumber||'', cardType: cardType||'', dob: dob||'', gender: gender||'',
      avatar: '', bonusMiles: 0, role: 'user', createdAt: new Date().toISOString()
    };
    users.push(newUser);
    await saveUsers(users);

    // initialize empty cart for user
    const carts = await loadCarts();
    carts[id] = carts[id] || [];
    await saveCarts(carts);

    // create session
    req.session.userId = id;

    const safe = {...newUser}; delete safe.password;
    res.json({ ok: true, user: safe });
  } catch (err) {
    console.error('register error', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// login
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
    const safe = {...user}; delete safe.password;
    res.json({ ok: true, user: safe });
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

// profile
app.get('/api/profile', async (req, res) => {
  try {
    if (!req.session.userId) return res.status(401).json({ error: 'Не авторизован' });
    const users = await loadUsers();
    const user = users.find(u => u.id === req.session.userId);
    if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
    const safe = {...user}; delete safe.password;
    res.json({ ok: true, user: safe });
  } catch (err) {
    console.error('profile error', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// update profile
app.post('/api/profile/update', async (req, res) => {
  try {
    if (!req.session.userId) return res.status(401).json({ error: 'Не авторизован' });
    const allowed = ['fio','phone','email','cardNumber','cardType','dob','gender','avatar','bonusMiles'];
    const users = await loadUsers();
    const user = users.find(u => u.id === req.session.userId);
    if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
    for (const k of allowed) {
      if (req.body[k] !== undefined) user[k] = req.body[k];
    }
    await saveUsers(users);
    const safe = {...user}; delete safe.password;
    res.json({ ok: true, user: safe });
  } catch (err) {
    console.error('profile update error', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/* ----------------- Cart API ----------------- */

// require auth middleware for cart endpoints
function requireAuth(req, res, next){
  if (!req.session.userId) return res.status(401).json({ error: 'Не авторизован' });
  next();
}

// get cart
app.get('/api/cart', requireAuth, async (req, res) => {
  try {
    const carts = await loadCarts();
    const items = carts[req.session.userId] || [];
    res.json({ ok: true, items });
  } catch (err) {
    console.error('cart get error', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// add to cart
app.post('/api/cart/add', requireAuth, async (req, res) => {
  try {
    const item = req.body;
    if (!item || !item.id) return res.status(400).json({ error: 'Неправильный item' });
    const carts = await loadCarts();
    carts[req.session.userId] = carts[req.session.userId] || [];
    carts[req.session.userId].push(item);
    await saveCarts(carts);
    res.json({ ok: true, items: carts[req.session.userId] });
  } catch (err) {
    console.error('cart add error', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// remove from cart: accepts { index } OR { id } (removes first match)
app.post('/api/cart/remove', requireAuth, async (req, res) => {
  try {
    const { index, id } = req.body || {};
    const carts = await loadCarts();
    const arr = carts[req.session.userId] || [];
    if (typeof index === 'number') {
      if (index < 0 || index >= arr.length) return res.status(400).json({ error: 'Неправильный индекс' });
      arr.splice(index, 1);
    } else if (id) {
      const i = arr.findIndex(it => it.id === id);
      if (i >= 0) arr.splice(i,1);
      else return res.status(404).json({ error: 'Товар не найден' });
    } else {
      return res.status(400).json({ error: 'Нужен index или id' });
    }
    carts[req.session.userId] = arr;
    await saveCarts(carts);
    res.json({ ok: true, items: arr });
  } catch (err) {
    console.error('cart remove error', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// clear cart
app.post('/api/cart/clear', requireAuth, async (req, res) => {
  try {
    const carts = await loadCarts();
    carts[req.session.userId] = [];
    await saveCarts(carts);
    res.json({ ok: true });
  } catch (err) {
    console.error('cart clear error', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// checkout: accepts { items } optionally; will create an order and clear cart
app.post('/api/cart/checkout', requireAuth, async (req, res) => {
  try {
    const provided = req.body && Array.isArray(req.body.items) ? req.body.items : null;
    const carts = await loadCarts();
    const items = provided || (carts[req.session.userId] || []);
    if (!items || items.length === 0) return res.status(400).json({ error: 'Корзина пуста' });

    const users = await loadUsers();
    const user = users.find(u => u.id === req.session.userId) || null;

    const orders = await loadOrders();
    const order = {
      id: Date.now().toString(36) + Math.random().toString(36).slice(2,8),
      userId: req.session.userId,
      items,
      createdAt: new Date().toISOString(),
      userSnapshot: { fio: user?.fio||'', phone: user?.phone||'', email: user?.email||'' }
    };
    orders.push(order);
    await saveOrders(orders);

    // clear server cart
    carts[req.session.userId] = [];
    await saveCarts(carts);

    res.json({ ok: true, orderId: order.id });
  } catch (err) {
    console.error('checkout error', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/* ----------------- Admin (optional) ----------------- */
// simple admin listing users (role==='admin')
app.get('/api/admin/users', requireAuth, async (req, res) => {
  try {
    const users = await loadUsers();
    const me = users.find(u => u.id === req.session.userId);
    if (!me || me.role !== 'admin') return res.status(403).json({ error: 'Нет доступа' });
    const safe = users.map(u => { const copy = {...u}; delete copy.password; return copy; });
    res.json({ ok: true, users: safe });
  } catch (err) {
    console.error('admin users error', err); res.status(500).json({ error: 'Internal server error' });
  }
});

/* ----------------- SPA fallback ----------------- */
// serve index.html for non-API routes (if you use a SPA)
app.get('*', (req, res) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ error: 'API endpoint not found' });
  const idx = path.join(PUBLIC_DIR, 'index.html');
  res.sendFile(idx);
});

/* ----------------- start ----------------- */
(async () => {
  try {
    await ensureDataFiles();
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
      console.log(`Public: ${PUBLIC_DIR}`);
      console.log(`Data dir: ${DATA_DIR}`);
    });
  } catch (err) {
    console.error('Failed to start server', err);
    process.exit(1);
  }
})();
