// server.js
// Полноценный сервер с users + cart + profile + file-based sessions
// Uses bcryptjs, express-session + session-file-store

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
const SESSIONS_DIR = path.join(__dirname, 'sessions');

// trust proxy for secure cookies behind proxy
if (process.env.NODE_ENV === 'production') {
  app.set('trust proxy', 1);
}

app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(PUBLIC_DIR));

const S_SECRET = process.env.SESSION_SECRET || 'please-change-this-secret';

// ==== Sessions on disk ====
app.use(session({
  name: 's7avelii.sid',
  secret: S_SECRET,
  resave: false,
  saveUninitialized: false,
  store: new FileStore({ path: SESSIONS_DIR, retries: 1 }),
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 1000 * 60 * 60 * 24 * 7 // 7 дней
  }
}));

// ==== Ensure data folder & files ====
async function ensureFiles() {
  await fsp.mkdir(DATA_DIR, { recursive: true });
  await fsp.mkdir(SESSIONS_DIR, { recursive: true });
  try { await fsp.access(USERS_FILE); } catch(e) { 
    await safeWrite(USERS_FILE, JSON.stringify([], null, 2));
  }
}

async function safeWrite(target, content) {
  const tmp = target + '.tmp-' + Date.now();
  await fsp.writeFile(tmp, content, 'utf8');
  await fsp.rename(tmp, target);
}

async function loadUsers() {
  await ensureFiles();
  const raw = await fsp.readFile(USERS_FILE, 'utf8');
  try { return JSON.parse(raw || '[]'); } 
  catch (e) { 
    console.error('users.json corrupted, resetting to []', e);
    await safeWrite(USERS_FILE, JSON.stringify([], null, 2));
    return [];
  }
}

async function saveUsers(users) {
  await ensureFiles();
  await safeWrite(USERS_FILE, JSON.stringify(users, null, 2));
}

// ==== Helpers ====
function makeId() { return Date.now().toString(36) + Math.random().toString(36).slice(2, 8); }
function withoutPassword(u) { const copy = { ...u }; delete copy.password; return copy; }

// ==== Auth / Profile API ====

// Register
app.post('/api/register', async (req, res) => {
  try {
    const { fio, phone, email, password, cardNumber, cardType, dob, gender } = req.body;
    if (!fio || !phone || !password) return res.status(400).json({ error: 'fio, phone, password обязательны' });

    const users = await loadUsers();
    if (email && users.find(u => u.email && u.email.toLowerCase() === String(email).toLowerCase())) 
      return res.status(400).json({ error: 'email уже зарегистрирован' });
    if (users.find(u => u.phone === phone)) 
      return res.status(400).json({ error: 'phone уже зарегистрирован' });

    const hashed = await bcrypt.hash(password, 10);
    const id = makeId();
    const newUser = {
      id, fio, phone, email: email || '', password: hashed,
      cardNumber: cardNumber || '', cardType: cardType || '', dob: dob || '', gender: gender || '',
      avatar: '', bonusMiles:0, role:'user', cart:[], createdAt: new Date().toISOString()
    };

    users.push(newUser);
    await saveUsers(users);

    req.session.userId = newUser.id; // <-- сохраняем сессию

    res.json({ ok:true, user: withoutPassword(newUser) });
  } catch (err) {
    console.error('register error', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { phone, email, password } = req.body;
    if ((!phone && !email) || !password) return res.status(400).json({ error: 'phone/email и пароль обязательны' });
    const users = await loadUsers();
    const user = users.find(u => (phone && u.phone === phone) || (email && u.email && u.email.toLowerCase() === String(email).toLowerCase()));
    if (!user) return res.status(400).json({ error:'Пользователь не найден' });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(400).json({ error:'Неверный пароль' });

    req.session.userId = user.id; // <-- сохраняем сессию
    res.json({ ok:true, user: withoutPassword(user) });
  } catch (err) { console.error('login error', err); res.status(500).json({ error:'Internal server error' }); }
});

// Logout
app.post('/api/logout', (req,res)=>{
  req.session.destroy(err=>{
    if(err) console.warn('session destroy error', err);
    res.clearCookie('s7avelii.sid');
    res.json({ok:true});
  });
});

// Get profile
app.get('/api/profile', async (req,res)=>{
  try{
    if(!req.session.userId) return res.status(401).json({error:'Не авторизован'});
    const users = await loadUsers();
    const user = users.find(u=>u.id===req.session.userId);
    if(!user) return res.status(404).json({error:'Пользователь не найден'});
    res.json({ok:true,user:withoutPassword(user)});
  }catch(err){ console.error(err); res.status(500).json({error:'Internal server error'}); }
});

// Update profile
async function handleProfileUpdate(req,res){
  try{
    if(!req.session.userId) return res.status(401).json({error:'Не авторизован'});
    const users = await loadUsers();
    const user = users.find(u=>u.id===req.session.userId);
    if(!user) return res.status(404).json({error:'Пользователь не найден'});
    const allowed = ['fio','phone','email','cardNumber','cardType','dob','gender','avatar','bonusMiles'];
    for(const k of allowed) if(req.body[k]!==undefined) user[k]=req.body[k];
    await saveUsers(users);
    res.json({ok:true,user:withoutPassword(user)});
  }catch(err){ console.error(err); res.status(500).json({error:'Internal server error'}); }
}
app.post('/api/profile/update', handleProfileUpdate);
app.post('/api/update-profile', handleProfileUpdate);

// ==== Cart API ====
app.post('/api/cart/add', async (req,res)=>{
  try{
    if(!req.session.userId) return res.status(401).json({error:'Не авторизован'});
    const item=req.body;
    const users = await loadUsers();
    const user = users.find(u=>u.id===req.session.userId);
    if(!user) return res.status(404).json({error:'Пользователь не найден'});
    user.cart = user.cart||[];
    user.cart.push({id:makeId(),addedAt:new Date().toISOString(),...item});
    await saveUsers(users);
    res.json({ok:true,cart:user.cart});
  }catch(err){ console.error(err); res.status(500).json({error:'Internal server error'}); }
});

app.get('/api/cart', async (req,res)=>{
  try{
    if(!req.session.userId) return res.status(401).json({error:'Не авторизован'});
    const users = await loadUsers();
    const user = users.find(u=>u.id===req.session.userId);
    if(!user) return res.status(404).json({error:'Пользователь не найден'});
    res.json({ok:true,cart:user.cart||[]});
  }catch(err){ console.error(err); res.status(500).json({error:'Internal server error'}); }
});

app.delete('/api/cart/:itemId', async (req,res)=>{
  try{
    if(!req.session.userId) return res.status(401).json({error:'Не авторизован'});
    const itemId=req.params.itemId;
    const users = await loadUsers();
    const user = users.find(u=>u.id===req.session.userId);
    if(!user) return res.status(404).json({error:'Пользователь не найден'});
    user.cart = (user.cart||[]).filter(i=>String(i.id)!==String(itemId));
    await saveUsers(users);
    res.json({ok:true,cart:user.cart});
  }catch(err){ console.error(err); res.status(500).json({error:'Internal server error'}); }
});

app.post('/api/cart/clear', async (req,res)=>{
  try{
    if(!req.session.userId) return res.status(401).json({error:'Не авторизован'});
    const users = await loadUsers();
    const user = users.find(u=>u.id===req.session.userId);
    if(!user) return res.status(404).json({error:'Пользователь не найден'});
    user.cart=[];
    await saveUsers(users);
    res.json({ok:true,cart:[]});
  }catch(err){ console.error(err); res.status(500).json({error:'Internal server error'}); }
});

// ==== Admin API ====
function isAdminMiddleware(req,res,next){
  if(!req.session.userId) return res.status(401).json({error:'Не авторизован'});
  loadUsers().then(users=>{
    const me=users.find(u=>u.id===req.session.userId);
    if(!me || me.role!=='admin') return res.status(403).json({error:'Нет доступа'});
    next();
  }).catch(err=>{ console.error(err); res.status(500).json({error:'Internal server error'}); });
}

app.get('/api/admin/users', isAdminMiddleware, async (req,res)=>{
  const users = await loadUsers();
  const safe = users.map(u=>{ const {password,...rest}=u; return rest; });
  res.json({ok:true,users:safe});
});

app.delete('/api/admin/users/:id', isAdminMiddleware, async (req,res)=>{
  const id = req.params.id;
  const users = await loadUsers();
  const remaining = users.filter(u=>u.id!==id);
  if(remaining.length===users.length) return res.status(404).json({error:'Пользователь не найден'});
  await saveUsers(remaining);
  res.json({ok:true});
});

// ==== SPA fallback ====
app.get('*', (req,res)=>{
  if(req.path.startsWith('/api/')) return res.status(404).json({error:'API not found'});
  const indexFile = path.join(PUBLIC_DIR,'index.html');
  if(fs.existsSync(indexFile)) return res.sendFile(indexFile);
  res.send('S7avelii server');
});

// ==== Start ====
(async()=>{
  try{
    await ensureFiles();
    app.listen(PORT,()=>console.log(`Server listening on ${PORT}`));
  }catch(err){ console.error('Failed to start', err); process.exit(1); }
})();
