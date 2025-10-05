// server.js — Render-ready, file-based users + persistent sessions

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

// Persistent data folder on Render (mount a persistent disk here)
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const SESSIONS_DIR = path.join(DATA_DIR, 'sessions');

if (process.env.NODE_ENV === 'production') app.set('trust proxy', 1);

app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Session store
const S_SECRET = process.env.SESSION_SECRET || 'please-change-this-secret';
app.use(session({
  name: 's7avelii.sid',
  secret: S_SECRET,
  store: new FileStore({ path: SESSIONS_DIR, ttl: 3600*24*7 }),
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 1000*60*60*24*7
  }
}));

// Ensure data dirs and files exist
async function ensureFiles() {
  await fsp.mkdir(DATA_DIR, { recursive: true });
  await fsp.mkdir(SESSIONS_DIR, { recursive: true });
  try {
    await fsp.access(USERS_FILE, fs.constants.F_OK);
  } catch (e) {
    await fsp.writeFile(USERS_FILE, JSON.stringify([], null, 2), 'utf8');
  }
}

async function loadUsers() {
  await ensureFiles();
  const raw = await fsp.readFile(USERS_FILE, 'utf8');
  try { return JSON.parse(raw || '[]'); }
  catch (e) { 
    console.error('users.json corrupted, resetting', e);
    await fsp.writeFile(USERS_FILE, JSON.stringify([], null, 2));
    return [];
  }
}

async function saveUsers(users) {
  await ensureFiles();
  await fsp.writeFile(USERS_FILE, JSON.stringify(users, null, 2), 'utf8');
}

function makeId() { return Date.now().toString(36) + Math.random().toString(36).slice(2, 8); }
function withoutPassword(u) { const c = { ...u }; delete c.password; return c; }

/* ---------- Auth API ---------- */
app.post('/api/register', async (req, res) => {
  try {
    const { fio, phone, email, password } = req.body;
    if (!fio || !phone || !password) return res.status(400).json({ error: 'fio, phone, password required' });

    const users = await loadUsers();
    if (email && users.find(u => u.email?.toLowerCase() === String(email).toLowerCase())) 
      return res.status(400).json({ error: 'Email already used' });
    if (users.find(u => u.phone === phone)) return res.status(400).json({ error: 'Phone already used' });

    const hashed = await bcrypt.hash(password, 10);
    const newUser = {
      id: makeId(), fio, phone, email: email||'', password: hashed,
      cardNumber:'', cardType:'', dob:'', gender:'', avatar:'',
      bonusMiles:0, role:'user', cart:[], createdAt:new Date().toISOString()
    };

    users.push(newUser);
    await saveUsers(users);

    req.session.userId = newUser.id;
    res.json({ ok: true, user: withoutPassword(newUser) });
  } catch (e) { console.error(e); res.status(500).json({ error:'Server error' }); }
});

app.post('/api/login', async (req, res) => {
  try {
    const { phone, email, password } = req.body;
    if ((!phone && !email) || !password) return res.status(400).json({ error: 'Phone/email and password required' });
    const users = await loadUsers();
    const user = users.find(u => (phone && u.phone===phone) || (email && u.email?.toLowerCase()===String(email).toLowerCase()));
    if (!user) return res.status(400).json({ error:'User not found' });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(400).json({ error:'Wrong password' });

    req.session.userId = user.id;
    res.json({ ok:true, user: withoutPassword(user) });
  } catch(e){ console.error(e); res.status(500).json({ error:'Server error' }); }
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(err => { if(err) console.warn(err); res.clearCookie('s7avelii.sid'); res.json({ok:true}); });
});

/* ---------- Profile API ---------- */
app.get('/api/profile', async (req,res) => {
  if(!req.session.userId) return res.status(401).json({error:'Unauthorized'});
  const users = await loadUsers();
  const user = users.find(u=>u.id===req.session.userId);
  if(!user) return res.status(404).json({error:'User not found'});
  res.json({ok:true, user: withoutPassword(user)});
});

app.post(['/api/profile/update','/api/update-profile'], async (req,res)=>{
  if(!req.session.userId) return res.status(401).json({error:'Unauthorized'});
  const users = await loadUsers();
  const user = users.find(u=>u.id===req.session.userId);
  if(!user) return res.status(404).json({error:'User not found'});

  const allowed=['fio','phone','email','cardNumber','cardType','dob','gender','avatar','bonusMiles'];
  allowed.forEach(k=>{ if(req.body[k]!==undefined) user[k]=req.body[k]; });
  await saveUsers(users);
  res.json({ok:true, user: withoutPassword(user)});
});

/* ---------- Cart API ---------- */
app.post('/api/cart/add', async(req,res)=>{
  if(!req.session.userId) return res.status(401).json({error:'Unauthorized'});
  const users = await loadUsers();
  const user = users.find(u=>u.id===req.session.userId);
  if(!user) return res.status(404).json({error:'User not found'});
  user.cart = user.cart||[];
  user.cart.push({ id: makeId(), addedAt: new Date().toISOString(), ...req.body });
  await saveUsers(users);
  res.json({ok:true, cart:user.cart});
});

app.get('/api/cart', async(req,res)=>{
  if(!req.session.userId) return res.status(401).json({error:'Unauthorized'});
  const users = await loadUsers();
  const user = users.find(u=>u.id===req.session.userId);
  if(!user) return res.status(404).json({error:'User not found'});
  res.json({ok:true, cart:user.cart||[]});
});

app.delete('/api/cart/:itemId', async(req,res)=>{
  if(!req.session.userId) return res.status(401).json({error:'Unauthorized'});
  const itemId=req.params.itemId;
  const users=await loadUsers();
  const user=users.find(u=>u.id===req.session.userId);
  if(!user) return res.status(404).json({error:'User not found'});
  user.cart=(user.cart||[]).filter(i=>String(i.id)!==String(itemId));
  await saveUsers(users);
  res.json({ok:true, cart:user.cart});
});

app.post('/api/cart/clear', async(req,res)=>{
  if(!req.session.userId) return res.status(401).json({error:'Unauthorized'});
  const users=await loadUsers();
  const user=users.find(u=>u.id===req.session.userId);
  if(!user) return res.status(404).json({error:'User not found'});
  user.cart=[];
  await saveUsers(users);
  res.json({ok:true, cart:[]});
});

/* ---------- SPA fallback ---------- */
app.get('*', (req,res)=>{
  if(req.path.startsWith('/api/')) return res.status(404).json({error:'API not found'});
  const indexFile = path.join(__dirname,'public','index.html');
  if(fs.existsSync(indexFile)) return res.sendFile(indexFile);
  res.send('S7avelii server');
});

/* ---------- Start ---------- */
(async()=>{
  try{
    await ensureFiles();
    app.listen(PORT,()=>console.log(`Server running on port ${PORT}`));
  }catch(err){ console.error('Failed to start',err); process.exit(1); }
})();
