// server.js
const express = require('express');
const session = require('express-session');
const FileStore = require('session-file-store')(session);
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

const PUBLIC_DIR = path.join(__dirname, 'public');
const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const SESSIONS_DIR = path.join(DATA_DIR, 'sessions');

// ========== Middleware ==========
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(PUBLIC_DIR));

// ========== Session ==========
const S_SECRET = process.env.SESSION_SECRET || 'please-change-this-secret';
app.use(session({
  store: new FileStore({ path: SESSIONS_DIR, retries: 1 }),
  name: 's7avelii.sid',
  secret: S_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 7*24*60*60*1000 // 7 дней
  }
}));

// ========== Ensure data dirs/files ==========
async function ensureFiles() {
  await fsp.mkdir(DATA_DIR, { recursive: true });
  await fsp.mkdir(SESSIONS_DIR, { recursive: true });
  try {
    await fsp.access(USERS_FILE, fs.constants.F_OK);
  } catch {
    await safeWrite(USERS_FILE, JSON.stringify([], null, 2));
  }
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
  catch {
    await safeWrite(USERS_FILE, JSON.stringify([], null, 2));
    return [];
  }
}

async function saveUsers(users) {
  await ensureFiles();
  await safeWrite(USERS_FILE, JSON.stringify(users, null, 2));
}

function makeId() { return Date.now().toString(36) + Math.random().toString(36).slice(2,8); }
function withoutPassword(u) { const copy = { ...u }; delete copy.password; return copy; }

// ========== Auth API ==========
app.post('/api/register', async (req, res) => {
  try {
    const { fio, phone, email, password } = req.body;
    if (!fio || !phone || !password) return res.status(400).json({ error: 'fio, phone и password обязательны' });

    const users = await loadUsers();
    if (email && users.find(u => u.email && u.email.toLowerCase() === String(email).toLowerCase()))
      return res.status(400).json({ error: 'Email уже зарегистрирован' });
    if (users.find(u => u.phone === phone))
      return res.status(400).json({ error: 'Телефон уже зарегистрирован' });

    const hashed = await bcrypt.hash(password, 10);
    const newUser = {
      id: makeId(),
      fio, phone, email: email||'', password: hashed,
      avatar: '', bonusMiles:0, role:'user', cart: [], createdAt: new Date().toISOString()
    };
    users.push(newUser);
    await saveUsers(users);

    req.session.userId = newUser.id;
    res.json({ ok:true, user: withoutPassword(newUser) });
  } catch(e){ res.status(500).json({ error:'Internal server error' }); }
});

app.post('/api/login', async (req,res)=>{
  try {
    const { phone, email, password } = req.body;
    if ((!phone && !email) || !password) return res.status(400).json({ error:'Нужен phone или email и пароль' });

    const users = await loadUsers();
    const user = users.find(u => (phone && u.phone===phone) || (email && u.email && u.email.toLowerCase()===String(email).toLowerCase()));
    if (!user) return res.status(400).json({ error:'Пользователь не найден' });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(400).json({ error:'Неверный пароль' });

    req.session.userId = user.id;
    res.json({ ok:true, user:withoutPassword(user) });
  } catch(e){ res.status(500).json({ error:'Internal server error' }); }
});

app.post('/api/logout', (req,res)=>{
  req.session.destroy(err=>{
    if(err) console.warn(err);
    res.clearCookie('s7avelii.sid');
    res.json({ ok:true });
  });
});

// ========== Profile ==========
app.get('/api/profile', async (req,res)=>{
  try {
    if(!req.session.userId) return res.status(401).json({ error:'Не авторизован' });
    const users = await loadUsers();
    const user = users.find(u=>u.id===req.session.userId);
    if(!user) return res.status(404).json({ error:'Пользователь не найден' });
    res.json({ ok:true, user:withoutPassword(user) });
  } catch(e){ res.status(500).json({ error:'Internal server error' }); }
});

app.post(['/api/profile/update','/api/update-profile'], async (req,res)=>{
  try {
    if(!req.session.userId) return res.status(401).json({ error:'Не авторизован' });
    const users = await loadUsers();
    const user = users.find(u=>u.id===req.session.userId);
    if(!user) return res.status(404).json({ error:'Пользователь не найден' });

    const allowed = ['fio','phone','email','avatar','bonusMiles','cardNumber','cardType','dob','gender'];
    allowed.forEach(k=>{ if(req.body[k]!==undefined) user[k]=req.body[k]; });

    await saveUsers(users);
    res.json({ ok:true, user:withoutPassword(user) });
  } catch(e){ res.status(500).json({ error:'Internal server error' }); }
});

// ========== Cart API ==========
app.post('/api/cart/add', async (req,res)=>{
  try {
    if(!req.session.userId) return res.status(401).json({ error:'Не авторизован' });
    const users = await loadUsers();
    const user = users.find(u=>u.id===req.session.userId);
    if(!user) return res.status(404).json({ error:'Пользователь не найден' });

    user.cart = user.cart || [];
    user.cart.push({ id:makeId(), addedAt:new Date().toISOString(), ...req.body });
    await saveUsers(users);
    res.json({ ok:true, cart:user.cart });
  } catch(e){ res.status(500).json({ error:'Internal server error' }); }
});

app.get('/api/cart', async (req,res)=>{
  try {
    if(!req.session.userId) return res.status(401).json({ error:'Не авторизован' });
    const users = await loadUsers();
    const user = users.find(u=>u.id===req.session.userId);
    if(!user) return res.status(404).json({ error:'Пользователь не найден' });
    res.json({ ok:true, cart:user.cart||[] });
  } catch(e){ res.status(500).json({ error:'Internal server error' }); }
});

app.delete('/api/cart/:itemId', async (req,res)=>{
  try {
    if(!req.session.userId) return res.status(401).json({ error:'Не авторизован' });
    const users = await loadUsers();
    const user = users.find(u=>u.id===req.session.userId);
    if(!user) return res.status(404).json({ error:'Пользователь не найден' });

    user.cart = (user.cart||[]).filter(i=>String(i.id)!==String(req.params.itemId));
    await saveUsers(users);
    res.json({ ok:true, cart:user.cart });
  } catch(e){ res.status(500).json({ error:'Internal server error' }); }
});

// ========== SPA fallback ==========
app.get('*', (req,res)=>{
  if(req.path.startsWith('/api/')) return res.status(404).json({ error:'API not found' });
  const indexFile = path.join(PUBLIC_DIR,'index.html');
  if(fs.existsSync(indexFile)) return res.sendFile(indexFile);
  res.send('S7avelii server');
});

// ========== Start ==========
(async()=>{
  try{
    await ensureFiles();
    app.listen(PORT,()=>console.log(`Server running on ${PORT}`));
  }catch(err){ console.error(err); process.exit(1); }
})();
