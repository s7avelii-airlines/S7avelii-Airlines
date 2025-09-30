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

// --- paths ---
const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const PUBLIC_DIR = path.join(__dirname, 'public');

// --- middlewares ---
app.use(express.json({ limit: '5mb' }));
app.use(cookieParser());

// serve static files (index.html, css, js)
app.use(express.static(PUBLIC_DIR));

// session configuration
const IS_PROD = process.env.NODE_ENV === 'production';
app.use(session({
  name: 's7avelii.sid',
  secret: process.env.SESSION_SECRET || 'please-change-this-to-a-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: IS_PROD,         // set true in production (https)
    sameSite: 'lax',
    maxAge: 1000 * 60 * 60 * 24 * 7 // 7 days
  }
}));

// --- helper: ensure data dir + file exists ---
async function ensureUsersFile() {
  try {
    await fsp.mkdir(DATA_DIR, { recursive: true });
    try {
      await fsp.access(USERS_FILE, fs.constants.F_OK);
    } catch (e) {
      // create initial empty array
      await safeWriteFile(USERS_FILE, JSON.stringify([], null, 2));
    }
  } catch (err) {
    console.error('Cannot ensure data dir/file:', err);
    throw err;
  }
}

// safe write: write to temp then rename
async function safeWriteFile(targetPath, content) {
  const tmp = targetPath + '.tmp-' + Date.now();
  await fsp.writeFile(tmp, content, { encoding: 'utf8' });
  await fsp.rename(tmp, targetPath);
}

// load users (reads fresh each call)
async function loadUsers() {
  await ensureUsersFile();
  const raw = await fsp.readFile(USERS_FILE, 'utf8');
  try {
    return JSON.parse(raw || '[]');
  } catch (e) {
    console.error('Invalid users.json — resetting to []', e);
    await safeWriteFile(USERS_FILE, JSON.stringify([], null, 2));
    return [];
  }
}

// save users
async function saveUsers(users) {
  await ensureUsersFile();
  await safeWriteFile(USERS_FILE, JSON.stringify(users, null, 2));
}

/* -----------------------
   API: register / login
   ----------------------- */

// register
app.post('/api/register', async (req, res) => {
  try {
    const { fio, phone, email, password, cardNumber, cardType, dob, gender } = req.body;
    if (!fio || !phone || !password) {
      return res.status(400).json({ error: 'Поля fio, phone и password обязательны' });
    }

    const users = await loadUsers();

    // check duplicates by email or phone
    if (email && users.find(u => u.email && u.email.toLowerCase() === email.toLowerCase())) {
      return res.status(400).json({ error: 'Пользователь с таким email уже зарегистрирован' });
    }
    if (users.find(u => u.phone === phone)) {
      return res.status(400).json({ error: 'Пользователь с таким телефоном уже зарегистрирован' });
    }

    const hashed = await bcrypt.hash(password, 10);
    const id = Date.now().toString(36) + Math.random().toString(36).slice(2,8);

    const newUser = {
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
      createdAt: new Date().toISOString()
    };

    users.push(newUser);
    await saveUsers(users);

    // create session
    req.session.userId = newUser.id;

    // return profile without password
    const safe = { ...newUser };
    delete safe.password;
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
    if ((!phone && !email) || !password) {
      return res.status(400).json({ error: 'Нужен phone или email и пароль' });
    }
    const users = await loadUsers();
    const user = users.find(u => (phone && u.phone === phone) || (email && u.email && u.email.toLowerCase() === email.toLowerCase()));
    if (!user) return res.status(400).json({ error: 'Пользователь не найден' });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(400).json({ error: 'Неверный пароль' });

    req.session.userId = user.id;
    const safe = { ...user }; delete safe.password;
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

// current profile
app.get('/api/profile', async (req, res) => {
  try {
    if (!req.session.userId) return res.status(401).json({ error: 'Не авторизован' });
    const users = await loadUsers();
    const user = users.find(u => u.id === req.session.userId);
    if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
    const safe = { ...user }; delete safe.password;
    res.json({ ok: true, user: safe });
  } catch (err) {
    console.error('profile error', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// update profile (auth required)
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
    const safe = { ...user }; delete safe.password;
    res.json({ ok: true, user: safe });
  } catch (err) {
    console.error('profile update error', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/* ========== Admin routes ========== */

// simple admin check by role
function isAdmin(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Не авторизован' });
  loadUsers().then(users => {
    const me = users.find(u => u.id === req.session.userId);
    if (!me || me.role !== 'admin') return res.status(403).json({ error: 'Нет доступа' });
    next();
  }).catch(err => {
    console.error('isAdmin error', err);
    res.status(500).json({ error: 'Internal server error' });
  });
}

// list users (no passwords)
app.get('/api/admin/users', isAdmin, async (req, res) => {
  const users = await loadUsers();
  const safe = users.map(u => {
    const copy = { ...u }; delete copy.password; return copy;
  });
  res.json({ ok: true, users: safe });
});

// delete user (admin)
app.delete('/api/admin/users/:id', isAdmin, async (req, res) => {
  const users = await loadUsers();
  const id = req.params.id;
  const remaining = users.filter(u => u.id !== id);
  if (remaining.length === users.length) return res.status(404).json({ error: 'Пользователь не найден' });
  await saveUsers(remaining);
  res.json({ ok: true });
});

/* -----------------------
   Fallback: if using SPA, return index.html
   ----------------------- */
app.get('*', (req, res) => {
  // If the request is for an API route, respond 404; otherwise return index.html
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ error: 'API endpoint not found' });
  }
  // serve index.html from public
  res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
});

/* -----------------------
   Start server
   ----------------------- */
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

