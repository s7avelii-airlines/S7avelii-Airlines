// server.js
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

// --- Middleware ---
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: false }));
app.use(express.static(PUBLIC_DIR));

app.use(session({
  name: 's7avelii.sid',
  secret: process.env.SESSION_SECRET || 'please-change-this-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, maxAge: 7*24*60*60*1000 } // 7 дней
}));

// --- Helpers ---
async function ensureFiles() {
  await fsp.mkdir(DATA_DIR, { recursive: true });
  try { await fsp.access(USERS_FILE); } 
  catch(e){ await safeWrite(USERS_FILE, '[]'); }
}

async function safeWrite(file, content) {
  const tmp = file + '.tmp-' + Date.now();
  await fsp.writeFile(tmp, content, 'utf8');
  await fsp.rename(tmp, file);
}

async function loadUsers() {
  await ensureFiles();
  const raw = await fsp.readFile(USERS_FILE, 'utf8');
  try { return JSON.parse(raw || '[]'); }
  catch(e){ await safeWrite(USERS_FILE,'[]'); return []; }
}

async function saveUsers(users){ await safeWrite(USERS_FILE, JSON.stringify(users,null,2)); }

function makeId(){ return Date.now().toString(36)+Math.random().toString(36).slice(2,8); }
function withoutPassword(u){ const c={...u}; delete c.password; return c; }

// --- Auth Routes ---

// Register
app.post('/api/register', async (req,res)=>{
  const { fio, dob, gender, email, phone, password, cardNumber, cardType } = req.body;
  if(!fio || !email || !phone || !password) return res.status(400).json({error:'Обязательные поля: ФИО, email, телефон, пароль'});
  const users = await loadUsers();
  if(users.find(u=>u.email?.toLowerCase()===email.toLowerCase())) return res.status(400).json({error:'Email уже зарегистрирован'});
  if(users.find(u=>u.phone===phone)) return res.status(400).json({error:'Телефон уже зарегистрирован'});
  const hashed = await bcrypt.hash(password,10);
  const newUser = { id:makeId(), fio, dob, gender, email, phone, password:hashed, cardNumber:cardNumber||'', cardType:cardType||'', avatar:'', bonusMiles:0, role:'user', cart:[], orders:[], createdAt:new Date().toISOString() };
  users.push(newUser);
  await saveUsers(users);
  req.session.userId = newUser.id;
  res.json({ ok:true, user: withoutPassword(newUser) });
});

// Login
app.post('/api/login', async (req,res)=>{
  const { phone, email, password } = req.body;
  if((!phone && !email) || !password) return res.status(400).json({error:'Нужен телефон/email и пароль'});
  const users = await loadUsers();
  const user = users.find(u=> (phone&&u.phone===phone) || (email&&u.email.toLowerCase()===email.toLowerCase()));
  if(!user) return res.status(400).json({error:'Пользователь не найден'});
  const ok = await bcrypt.compare(password,user.password);
  if(!ok) return res.status(400).json({error:'Неверный пароль'});
  req.session.userId = user.id;
  res.json({ ok:true, user: withoutPassword(user) });
});

// Logout
app.post('/api/logout', (req,res)=>{
  req.session.destroy(err=>{ if(err) console.warn(err); res.clearCookie('s7avelii.sid'); res.json({ok:true}); });
});

// Profile
app.get('/api/profile', async (req,res)=>{
  if(!req.session.userId) return res.status(401).json({error:'Не авторизован'});
  const users = await loadUsers();
  const user = users.find(u=>u.id===req.session.userId);
  if(!user) return res.status(404).json({error:'Пользователь не найден'});
  res.json({ ok:true, user:withoutPassword(user) });
});

// Update profile
app.post(['/api/profile/update','/api/update-profile'], async (req,res)=>{
  if(!req.session.userId) return res.status(401).json({error:'Не авторизован'});
  const users = await loadUsers();
  const user = users.find(u=>u.id===req.session.userId);
  if(!user) return res.status(404).json({error:'Пользователь не найден'});
  const allowed=['fio','dob','gender','email','phone','cardNumber','cardType','avatar','bonusMiles','password'];
  for(const k of allowed) if(req.body[k]!==undefined) user[k]=req.body[k];
  await saveUsers(users);
  res.json({ ok:true, user:withoutPassword(user) });
});

// --- Cart ---
app.get('/api/cart', async (req,res)=>{
  if(!req.session.userId) return res.status(401).json({error:'Не авторизован'});
  const users = await loadUsers();
  const user = users.find(u=>u.id===req.session.userId);
  if(!user) return res.status(404).json({error:'Пользователь не найден'});
  res.json({ ok:true, cart: user.cart||[] });
});

app.post('/api/cart/add', async (req,res)=>{
  if(!req.session.userId) return res.status(401).json({error:'Не авторизован'});
  const item = req.body;
  const users = await loadUsers();
  const user = users.find(u=>u.id===req.session.userId);
  if(!user) return res.status(404).json({error:'Пользователь не найден'});
  user.cart = user.cart||[];
  user.cart.push({ id:makeId(), addedAt:new Date().toISOString(), ...item });
  await saveUsers(users);
  res.json({ ok:true, cart:user.cart });
});

app.post('/api/cart/clear', async (req,res)=>{
  if(!req.session.userId) return res.status(401).json({error:'Не авторизован'});
  const users = await loadUsers();
  const user = users.find(u=>u.id===req.session.userId);
  if(!user) return res.status(404).json({error:'Пользователь не найден'});
  user.cart = [];
  await saveUsers(users);
  res.json({ ok:true, cart:[] });
});

// Checkout (создание заказа)
app.post('/api/cart/checkout', async (req,res)=>{
  if(!req.session.userId) return res.status(401).json({error:'Не авторизован'});
  const users = await loadUsers();
  const user = users.find(u=>u.id===req.session.userId);
  if(!user) return res.status(404).json({error:'Пользователь не найден'});
  if(!user.cart || !user.cart.length) return res.status(400).json({error:'Корзина пуста'});
  const total = user.cart.reduce((sum,it)=>{
    const price = parseFloat((it.price||'').replace(/[^\d,.-]/g,'').replace(',','.'))||0;
    return sum + price*(it.qty||1);
  },0);
  const order = { id:makeId(), createdAt:new Date().toISOString(), status:'Принят', items:user.cart, total };
  user.orders = user.orders||[];
  user.orders.push(order);
  user.cart = [];
  await saveUsers(users);
  res.json({ ok:true, order });
});

// --- SPA fallback ---
app.get('*', (req,res)=>{
  if(req.path.startsWith('/api/')) return res.status(404).json({error:'API not found'});
  const indexFile = path.join(PUBLIC_DIR,'index.html');
  if(fs.existsSync(indexFile)) return res.sendFile(indexFile);
  res.send('S7avelii server');
});

// --- Start ---
(async()=>{
  try{ await ensureFiles(); app.listen(PORT,()=>{ console.log(`Server running on port ${PORT}`); }); }
  catch(err){ console.error('Failed to start', err); process.exit(1); }
})();
