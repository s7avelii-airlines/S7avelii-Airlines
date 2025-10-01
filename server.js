// server.js
// Express server for S7avelii — static + auth + users.json storage
// Requirements: express, express-session, cookie-parser, cors, bcrypt
// Install: npm install express express-session cookie-parser cors bcrypt

const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// config via env
const SESSION_SECRET = process.env.SESSION_SECRET || 'change_this_secret_in_prod';
const CLIENT_ORIGIN = process.env.CLIENT_ORIGIN || true; // if set to string, CORS will allow that origin; otherwise reflect origin
const NODE_ENV = process.env.NODE_ENV || 'development';
const IS_PROD = NODE_ENV === 'production';

// file paths
const PUBLIC_DIR = path.join(__dirname, 'public');
const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');

// convenience
app.use(express.json({ limit: '5mb' }));
app.use(cookieParser());

// IMPORTANT for deployments behind proxies (Render, Heroku, etc.)
if (IS_PROD) {
  app.set('trust proxy', 1); // trust first proxy
}

// CORS: allow credentials. If CLIENT_ORIGIN is not set, cors origin: true will echo request origin.
app.use(cors({
  origin: CLIENT_ORIGIN,
  credentials: true,
}));

// session
app.use(session({
  name: 's7avelii.sid',
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: IS_PROD,       // only send cookie via HTTPS in production
    sameSite: 'lax',
    maxAge: 1000 * 60 * 60 * 24 * 14 // 14 days
  }
}));

// serve static files
app.use(express.static(PUBLIC_DIR));

/* ---------------------------
   File helpers (atomic)
   --------------------------- */

async function ensureDataDirAndFile() {
  await fsp.mkdir(DATA_DIR, { recursive: true });
  try {
    await fsp.access(USERS_FILE, fs.constants.F_OK);
  } catch (e) {
    await safeWriteFile(USERS_FILE, JSON.stringify([], null, 2));
  }
}

async function safeWriteFile(targetPath, content) {
  const tmp = targetPath + '.tmp-' + Date.now();
  await fsp.writeFile(tmp, content, { encoding: 'utf8' });
  await fsp.rename(tmp, targetPath);
}

async function loadUsers() {
  await ensureDataDirAndFile();
  const raw = await fsp.readFile(USERS_FILE, 'utf8');
  try {
    return JSON.parse(raw || '[]');
  } catch (err) {
    console.error('users.json parse error — resetting file', err);
    await safeWriteFile(USERS_FILE, JSON.stringify([], null, 2));
    return [];
  }
}

async function saveUsers(users) {
  await ensureDataDirAndFile();
  await safeWriteFile(USERS_FILE, JSON.stringify(users, null, 2));
}

function sanitizeUserForClient(user) {
  if (!user) return null;
  const copy = { ...user };
  delete copy.password;
  return copy;
}

function genId() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
}

/* ---------------------------
   Optional: create initial admin if env set
   --------------------------- */
async function ensureAdmin() {
  const adminEmail = process.env.ADMIN_EMAIL;
  const adminPassword = process.env.ADMIN_PASSWORD;
  if (!adminEmail || !adminPassword) return;
  const users = await loadUsers();
  const found = users.find(u => u.email && u.email.toLowerCase() === adminEmail.toLowerCase());
  if (found) return;
  const hashed = await bcrypt.hash(adminPassword, 10);
  const admin = {
    id: genId(),
    fio: 'Admin',
    email: adminEmail,
    phone: '',
    password: hashed,
    role: 'admin',
    createdAt: new Date().toISOString()
  };
  users.push(admin);
  await saveUsers(users);
  console.log('Created initial admin:', adminEmail);
}

/* ---------------------------
   Auth / API routes
   --------------------------- */

// register
app.post('/api/register', async (req, res) => {
  try {
    const { fio, phone, email, password, cardNumber, cardType, dob, gender, avatar } = req.body || {};
    if (!fio || !phone || !password) {
      return res.status(400).json({ error: 'Поля fio, phone и password обязательны' });
    }

    const users = await loadUsers();

    // uniqueness checks
    if (email && users.find(u => u.email && u.email.toLowerCase() === email.toLowerCase())) {
      return res.status(400).json({ error: 'Пользователь с таким email уже зарегистрирован' });
    }
    if (users.find(u => u.phone === phone)) {
      return res.status(400).json({ error: 'Пользователь с таким телефоном уже зарегистрирован' });
    }

    const hashed = await bcrypt.hash(password, 10);
    const id = genId();
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
      avatar: avatar || '',
      bonusMiles: 0,
      role: 'user',
      createdAt: new Date().toISOString()
    };

    users.push(newUser);
    await saveUsers(users);

    // set session
    req.session.userId = newUser.id;

    res.json({ ok: true, user: sanitizeUserForClient(newUser) });
  } catch (err) {
    console.error('register error', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// login
app.post('/api/login', async (req, res) => {
  try {
    const { phone, email, password } = req.body || {};
    if ((!phone && !email) || !password) {
      return res.status(400).json({ error: 'Нужен phone или email и пароль' });
    }

    const users = await loadUsers();
    const user = users.find(u =>
      (phone && u.phone === phone) ||
      (email && u.email && u.email.toLowerCase() === email.toLowerCase())
    );

    if (!user) return res.status(400).json({ error: 'Пользователь не найден' });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(400).json({ error: 'Неверный пароль' });

    req.session.userId = user.id;

    res.json({ ok: true, user: sanitizeUserForClient(user) });
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

// profile (current user)
app.get('/api/profile', async (req, res) => {
  try {
    if (!req.session.userId) return res.status(401).json({ error: 'Не авторизован' });
    const users = await loadUsers();
    const user = users.find(u => u.id === req.session.userId);
    if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
    res.json(sanitizeUserForClient(user));
  } catch (err) {
    console.error('profile error', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// update profile
app.post('/api/update-profile', async (req, res) => {
  try {
    if (!req.session.userId) return res.status(401).json({ error: 'Не авторизован' });
    const users = await loadUsers();
    const idx = users.findIndex(u => u.id === req.session.userId);
    if (idx === -1) return res.status(404).json({ error: 'Пользователь не найден' });

    // allowed fields to update
    const allowed = ['fio','phone','email','cardNumber','cardType','dob','gender','avatar','bonusMiles'];
    for (const k of allowed) {
      if (req.body[k] !== undefined) users[idx][k] = req.body[k];
    }

    await saveUsers(users);
    req.session.userId = users[idx].id; // keep session
    res.json({ ok: true, user: sanitizeUserForClient(users[idx]) });
  } catch (err) {
    console.error('update-profile error', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/* ---------------------------
   Admin endpoints
   --------------------------- */

async function requireAdmin(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Не авторизован' });
  const users = await loadUsers();
  const me = users.find(u => u.id === req.session.userId);
  if (!me || me.role !== 'admin') return res.status(403).json({ error: 'Нет доступа' });
  req.me = me;
  next();
}

app.get('/api/admin/users', requireAdmin, async (req, res) => {
  const users = await loadUsers();
  const list = users.map(u => sanitizeUserForClient(u));
  res.json({ ok: true, users: list });
});

app.delete('/api/admin/users/:id', requireAdmin, async (req, res) => {
  const id = req.params.id;
  const users = await loadUsers();
  const remaining = users.filter(u => u.id !== id);
  if (remaining.length === users.length) return res.status(404).json({ error: 'Пользователь не найден' });
  await saveUsers(remaining);
  res.json({ ok: true });
});

/* ---------------------------
   Fallback - SPA support
   --------------------------- */
app.get('*', (req, res) => {
  // For API routes, return 404
  if (req.path.startsWith('/api/')) return res.status(404).json({ error: 'API endpoint not found' });
  // otherwise serve index.html from public
  const index = path.join(PUBLIC_DIR, 'index.html');
  if (fs.existsSync(index)) return res.sendFile(index);
  res.status(404).send('Not found');
});

/* ---------------------------
   Start server
   --------------------------- */
(async () => {
  try {
    await ensureDataDirAndFile();
    await ensureAdmin(); // optional
    app.listen(PORT, () => {
      console.log(`Server listening on port ${PORT}`);
      console.log(`Public dir: ${PUBLIC_DIR}`);
      console.log(`Users file: ${USERS_FILE}`);
    });
  } catch (err) {
    console.error('Failed to start server', err);
    process.exit(1);
  }
})();

