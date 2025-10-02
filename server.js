const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const fs = require('fs').promises;
const path = require('path');

const app = express();
const PORT = 3000;

const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const PUBLIC_DIR = path.join(__dirname, 'public');

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(express.static(PUBLIC_DIR));

// Session
app.use(session({
  secret: 'secret_s7avelii',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000*60*60*24*7 }
}));

// Ensure users.json exists
async function ensureUsersFile() {
  try { await fs.access(USERS_FILE); } 
  catch { await fs.mkdir(DATA_DIR, { recursive:true }); await fs.writeFile(USERS_FILE,'[]'); }
}
async function loadUsers() { await ensureUsersFile(); const data = await fs.readFile(USERS_FILE,'utf8'); return JSON.parse(data||'[]'); }
async function saveUsers(users){ await fs.writeFile(USERS_FILE, JSON.stringify(users,null,2)); }

// Helpers
function withoutPassword(u){ const copy = {...u}; delete copy.password; return copy; }
function makeId(){ return Date.now().toString(36)+Math.random().toString(36).slice(2,8); }

// ---------- REGISTER ----------
app.post('/api/register', async (req,res)=>{
  const { fio, phone, email, password } = req.body;
  if(!fio||!phone||!password) return res.status(400).json({error:'ФИО, телефон и пароль обязательны'});

  const users = await loadUsers();
  if(users.find(u=>u.phone===phone)) return res.status(400).json({error:'Телефон занят'});
  if(email && users.find(u=>u.email===email)) return res.status(400).json({error:'Email занят'});

  const hashed = await bcrypt.hash(password,10);
  const newUser = { id:makeId(), fio, phone, email: email||'', password:hashed, cart:[], orders:[], bonusMiles:0 };
  users.push(newUser);
  await saveUsers(users);
  req.session.userId = newUser.id;
  res.json({ok:true, user: withoutPassword(newUser)});
});

// ---------- LOGIN ----------
app.post('/api/login', async (req,res)=>{
  const { phone, password } = req.body;
  if(!phone||!password) return res.status(400).json({error:'Телефон и пароль обязательны'});

  const users = await loadUsers();
  const user = users.find(u=>u.phone===phone);
  if(!user) return res.status(400).json({error:'Пользователь не найден'});

  const ok = await bcrypt.compare(password,user.password);
  if(!ok) return res.status(400).json({error:'Неверный пароль'});

  req.session.userId = user.id;
  res.json({ok:true, user: withoutPassword(user)});
});

// ---------- LOGOUT ----------
app.post('/api/logout', (req,res)=>{ req.session.destroy(()=>res.json({ok:true})); });

// ---------- GET PROFILE ----------
app.get('/api/profile', async (req,res)=>{
  if(!req.session.userId) return res.status(401).json({error:'Не авторизован'});
  const users = await loadUsers();
  const user = users.find(u=>u.id===req.session.userId);
  if(!user) return res.status(404).json({error:'Не найден'});
  res.json({ok:true, user: withoutPassword(user)});
});

// ---------- SPA fallback ----------
app.get('*',(req,res)=> res.sendFile(path.join(PUBLIC_DIR,'auth.html')));

// Start
app.listen(PORT,()=>console.log(`Server running on http://localhost:${PORT}`));

