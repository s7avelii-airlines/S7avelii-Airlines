const express = require('express');
const fs = require('fs');
const path = require('path');
const session = require('express-session');

const app = express();
const PORT = process.env.PORT || 3000;
const USERS_FILE = path.join(__dirname, 'users.json');

// --- Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: 'supersecretkey',  // замени на свой ключ!
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 } // 7 дней
}));

// --- Helpers
function readUsers() {
  if (!fs.existsSync(USERS_FILE)) return [];
  return JSON.parse(fs.readFileSync(USERS_FILE, 'utf-8') || '[]');
}
function writeUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

// --- API
app.post('/api/register', (req, res) => {
  const users = readUsers();
  const { fio, dob, gender, email, phone, card, cardType, password } = req.body;

  if (!fio || !phone || !password) {
    return res.status(400).json({ error: 'Обязательные поля не заполнены' });
  }

  if (users.find(u => u.phone === phone)) {
    return res.status(400).json({ error: 'Телефон уже зарегистрирован' });
  }

  const newUser = { fio, dob, gender, email, phone, card, cardType, password };
  users.push(newUser);
  writeUsers(users);

  req.session.user = newUser;
  res.json({ success: true });
});

app.post('/api/login', (req, res) => {
  const users = readUsers();
  const { phone, password } = req.body;

  const user = users.find(u => u.phone === phone && u.password === password);
  if (!user) return res.status(400).json({ error: 'Неверные данные' });

  req.session.user = user;
  res.json({ success: true });
});

app.get('/api/profile', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Не авторизован' });
  res.json(req.session.user);
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true });
  });
});

// --- Запуск
app.listen(PORT, () => {
  console.log(`✅ Сервер запущен: http://localhost:${PORT}`);
});

