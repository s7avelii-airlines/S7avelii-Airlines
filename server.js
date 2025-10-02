// server.js
// Полноценный сервер для S7avelii: регистрация, вход, сессии, корзина, checkout

const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const PUBLIC_DIR = path.join(__dirname, 'public');

// Middleware
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: false }));
app.use(express.static(PUBLIC_DIR));

const S_SECRET = process.env.SESSION_SECRET || 'change_this_secret';
app.use(session({
  name: 's7avelii.sid',
  secret: S_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 1000*60*60*24*7 // 7 дней
  }
}));

// Helper functions
async function ensureFiles() {
  await fsp.mkdir(DATA_DIR, { recursive: true });
  try {
    await fsp.access(USERS_FILE);
  } catch {
    await fsp.writeFile(USERS_FILE, '[]', 'utf-8');
  }
}

async function loadUsers() {
  await ensureFiles();
  const raw = await fsp.readFile(USERS_FILE, 'utf-8');
  return JSON.parse(raw || '[]');
}

async function saveUsers(users) {
  await ensureFiles();
  await fsp.writeFile(USERS_FILE, JSON.stringify(users, null, 2), 'utf-8');
}

function withoutPassword(user) {
  const u = { ...user };
  delete u.password;
  return u;
}

function makeId() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2,8);
}

// ---------- Auth ----------

// Register
app.post('/api/register', async (req,res)=>{
  const { fio, phone, email, password, cardNumber, cardType, dob, gender } = req.body;
  if(!fio || !phone || !password) return res.status(400).json({ error:'fio, phone и password обязательны' });

  const users = await loadUsers();
  if(email && users.find(u => u.email && u.email.toLowerCase()===String(email).toLowerCase()))
    return res.status(400).json({ error:'Email уже используется' });
  if(users.find(u => u.phone===phone))
    return res.status(400).json({ error:'Телефон уже используется' });

  const hashed = await bcrypt.hash(password, 10);
  const newUser = {
    id: makeId(),
    fio, phone, email: email||'', password: hashed,
    cardNumber: cardNumber||'', cardType: cardType||'',
    dob: dob||'', gender: gender||'',
    avatar:'', bonusMiles:0, role:'user', cart:[], orders:[], createdAt:new Date().toISOString()
  };
  users.push(newUser);
  await saveUsers(users);

  req.session.userId = newUser.id;
  res.json({ ok:true, user: withoutPassword(newUser) });
});

// Login
app.post('/api/login', async (req,res)=>{
  const { phone, email, password } = req.body;
  if((!phone && !email) || !password) return res.status(400).json({ error:'Нужен phone или email и пароль' });

  const users = await loadUsers();
  const user = users.find(u => (phone && u.phone===phone) || (email && u.email && u.email.toLowerCase()===String(email).toLowerCase()));
  if(!user) return res.status(400).json({ error:'Пользователь не найден' });

  const ok = await bcrypt.compare(password, user.password);
  if(!ok) return res.status(400).json({ error:'Неверный пароль' });

  req.session.userId = user.id;
  res.json({ ok:true, user: withoutPassword(user) });
});

// Logout
app.post('/api/logout', (req,res)=>{
  req.session.destroy(()=>{});
  res.clearCookie('s7avelii.sid');
  res.json({ ok:true });
});

// Profile
app.get('/api/profile', async (req,res)=>{
  if(!req.session.userId) return res.status(401).json({ error:'Не авторизован' });
  const users = await loadUsers();
  const user = users.find(u => u.id===req.session.userId);
  if(!user) return res.status(404).json({ error:'Пользователь не найден' });
  res.json({ ok:true, user: withoutPassword(user) });
});

// Update profile
app.post(['/api/update-profile','/api/profile/update'], async (req,res)=>{
  if(!req.session.userId) return res.status(401).json({ error:'Не авторизован' });
  const users = await loadUsers();
  const user = users.find(u => u.id===req.session.userId);
  if(!user) return res.status(404).json({ error:'Пользователь не найден' });

  const allowed = ['fio','phone','email','cardNumber','cardType','dob','gender','avatar','bonusMiles','password'];
  for(const k of allowed) if(req.body[k]!==undefined) user[k]=req.body[k];

  await saveUsers(users);
  res.json({ ok:true, user: withoutPassword(user) });
});

// ---------- Cart ----------

// Add
app.post('/api/cart/add', async (req,res)=>{
  if(!req.session.userId) return res.status(401).json({ error:'Не авторизован' });
  const item = req.body;
  const users = await loadUsers();
  const user = users.find(u => u.id===req.session.userId);
  if(!user) return res.status(404).json({ error:'Пользователь не найден' });
  user.cart.push({ id: makeId(), addedAt:new Date().toISOString(), ...item });
  await saveUsers(users);
  res.json({ ok:true, cart:user.cart });
});

// Get cart
app.get('/api/cart', async (req,res)=>{
  if(!req.session.userId) return res.status(401).json({ error:'Не авторизован' });
  const users = await loadUsers();
  const user = users.find(u => u.id===req.session.userId);
  res.json({ ok:true, cart: user.cart||[] });
});

// Remove item
app.post('/api/cart/remove', async (req,res)=>{
  if(!req.session.userId) return res.status(401).json({ error:'Не авторизован' });
  const { id } = req.body;
  const users = await loadUsers();
  const user = users.find(u => u.id===req.session.userId);
  user.cart = (user.cart||[]).filter(i => i.id!==id);
  await saveUsers(users);
  res.json({ ok:true, cart:user.cart });
});

// Clear
app.post('/api/cart/clear', async (req,res)=>{
  if(!req.session.userId) return res.status(401).json({ error:'Не авторизован' });
  const users = await loadUsers();
  const user = users.find(u => u.id===req.session.userId);
  user.cart=[];
  await saveUsers(users);
  res.json({ ok:true, cart:[] });
});

// ---------- Checkout ----------
app.post('/api/cart/checkout', async (req,res)=>{
  if(!req.session.userId) return res.status(401).json({ error:'Не авторизован' });
  const users = await loadUsers();
  const user = users.find(u => u.id===req.session.userId);
  if(!user) return res.status(404).json({ error:'Пользователь не найден' });
  if(!user.cart || user.cart.length===0) return res.status(400).json({ error:'Корзина пуста' });

  const total = user.cart.reduce((acc,i)=> acc + Number(String(i.price||0).replace(/[^\d]/g,'')) * (i.qty||1), 0);

  const order = {
    id: 'order_'+Date.now(),
    createdAt: new Date().toISOString(),
    items: user.cart,
    total,
    status: 'Новый'
  };

  user.orders = user.orders||[];
  user.orders.push(order);
  user.cart = [];

  await saveUsers(users);
  res.json({ ok:true, order });
});

// ---------- SPA fallback ----------
app.get('*', (req,res)=>{
  if(req.path.startsWith('/api/')) return res.status(404).json({ error:'API not found' });
  const indexFile = path.join(PUBLIC_DIR,'index.html');
  if(fs.existsSync(indexFile)) return res.sendFile(indexFile);
  res.send('S7avelii server');
});

// ---------- Start ----------
(async()=>{
  try{
    await ensureFiles();
    app.listen(PORT,()=>console.log(`Server running at http://localhost:${PORT}`));
  } catch(e){
    console.error(e);
    process.exit(1);
  }
})();
