// server.js
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const fs = require('fs').promises;
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

const PUBLIC_DIR = path.join(__dirname, 'public');
const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');

// Middleware
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: false }));
app.use(express.static(PUBLIC_DIR));

// Session
app.use(session({
  name: 's7avelii.sid',
  secret: process.env.SESSION_SECRET || 'change_this_secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    maxAge: 1000 * 60 * 60 * 24 * 7
  }
}));

// Ensure data folder and users.json
async function ensureFiles() {
  await fs.mkdir(DATA_DIR, { recursive: true });
  try {
    await fs.access(USERS_FILE);
  } catch {
    await fs.writeFile(USERS_FILE, JSON.stringify([], null, 2));
  }
}

// Load/save users
async function loadUsers() {
  await ensureFiles();
  const data = await fs.readFile(USERS_FILE, 'utf8');
  return JSON.parse(data || '[]');
}
async function saveUsers(users) {
  await fs.writeFile(USERS_FILE, JSON.stringify(users, null, 2));
}

// Helpers
function withoutPassword(u) {
  const copy = { ...u };
  delete copy.password;
  return copy;
}
function makeId() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2,8);
}

// -------- AUTH --------

// Register
app.post('/api/register', async (req, res) => {
  const { fio, phone, email, password, dob, gender, cardNumber, cardType } = req.body;
  if (!fio || !phone || !password) return res.status(400).json({ error: 'ФИО, телефон и пароль обязательны' });
  
  const users = await loadUsers();
  if (email && users.find(u => u.email && u.email.toLowerCase() === email.toLowerCase())) 
    return res.status(400).json({ error: 'Email занят' });
  if (users.find(u => u.phone === phone)) return res.status(400).json({ error: 'Телефон занят' });

  const hashed = await bcrypt.hash(password, 10);
  const newUser = {
    id: makeId(),
    fio, phone, email: email||'', password: hashed,
    dob: dob||'', gender: gender||'', avatar:'', bonusMiles:0,
    cardNumber: cardNumber||'', cardType: cardType||'',
    cart: [], orders: [], role:'user', createdAt: new Date().toISOString()
  };
  users.push(newUser);
  await saveUsers(users);
  req.session.userId = newUser.id;
  res.json({ ok: true, user: withoutPassword(newUser) });
});

// Login
app.post('/api/login', async (req, res) => {
  const { phone, email, password } = req.body;
  if ((!phone && !email) || !password) return res.status(400).json({ error: 'Нужен phone/email и пароль' });

  const users = await loadUsers();
  const user = users.find(u => (phone && u.phone === phone) || (email && u.email && u.email.toLowerCase() === email.toLowerCase()));
  if (!user) return res.status(400).json({ error: 'Пользователь не найден' });

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(400).json({ error: 'Неверный пароль' });

  req.session.userId = user.id;
  res.json({ ok: true, user: withoutPassword(user) });
});

// Logout
app.post('/api/logout', (req, res) => {
  req.session.destroy(err => {
    res.clearCookie('s7avelii.sid');
    res.json({ ok:true });
  });
});

// Get profile
app.get('/api/profile', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Не авторизован' });
  const users = await loadUsers();
  const user = users.find(u => u.id === req.session.userId);
  if (!user) return res.status(404).json({ error: 'Не найден' });
  res.json({ ok:true, user: withoutPassword(user) });
});

// Update profile
app.post('/api/profile/update', async (req,res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Не авторизован' });
  const users = await loadUsers();
  const user = users.find(u => u.id === req.session.userId);
  if (!user) return res.status(404).json({ error: 'Не найден' });

  const allowed = ['fio','phone','email','dob','gender','avatar','cardNumber','cardType','bonusMiles','password'];
  for (const k of allowed) {
    if (req.body[k] !== undefined) user[k] = req.body[k];
  }
  await saveUsers(users);
  res.json({ ok:true, user: withoutPassword(user) });
});

// -------- CART & CHECKOUT --------

// Add item
app.post('/api/cart/add', async (req,res)=>{
  if (!req.session.userId) return res.status(401).json({ error: 'Не авторизован' });
  const users = await loadUsers();
  const user = users.find(u=>u.id===req.session.userId);
  if (!user) return res.status(404).json({ error: 'Не найден' });
  const item = { id: makeId(), addedAt: new Date().toISOString(), ...req.body };
  user.cart.push(item);
  await saveUsers(users);
  res.json({ ok:true, cart:user.cart });
});

// Get cart
app.get('/api/cart', async (req,res)=>{
  if (!req.session.userId) return res.status(401).json({ error: 'Не авторизован' });
  const users = await loadUsers();
  const user = users.find(u=>u.id===req.session.userId);
  if (!user) return res.status(404).json({ error: 'Не найден' });
  res.json({ ok:true, cart:user.cart });
});

// Clear cart
app.post('/api/cart/clear', async (req,res)=>{
  if (!req.session.userId) return res.status(401).json({ error: 'Не авторизован' });
  const users = await loadUsers();
  const user = users.find(u=>u.id===req.session.userId);
  if (!user) return res.status(404).json({ error: 'Не найден' });
  user.cart = [];
  await saveUsers(users);
  res.json({ ok:true, cart:[] });
});

// Checkout
app.post('/api/cart/checkout', async (req,res)=>{
  if (!req.session.userId) return res.status(401).json({ error:'Не авторизован' });
  const users = await loadUsers();
  const user = users.find(u=>u.id===req.session.userId);
  if (!user) return res.status(404).json({ error:'Не найден' });
  if (!user.cart.length) return res.status(400).json({ error:'Корзина пуста' });

  const total = user.cart.reduce((sum,i)=>sum + (parseFloat(i.price)||0)*(i.qty||1),0);
  const order = { id: makeId(), items: user.cart, total, createdAt: new Date().toISOString(), status:'Новый' };
  user.orders.push(order);
  user.cart = [];
  await saveUsers(users);
  res.json({ ok:true, order });
});

// -------- SPA fallback --------
app.get('*', (req,res)=>{
  if (req.path.startsWith('/api/')) return res.status(404).json({ error:'API not found' });
  const indexFile = path.join(PUBLIC_DIR, 'index.html');
  if (fs.existsSync(indexFile)) return res.sendFile(indexFile);
  res.send('S7avelii server');
});

// -------- START SERVER --------
(async ()=>{
  await ensureFiles();
  app.listen(PORT, ()=>console.log(`Server listening on port ${PORT}`));
})();

