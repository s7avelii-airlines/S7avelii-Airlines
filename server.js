const express = require('express');
const fs = require('fs');
const path = require('path');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const crypto = require('crypto');

const app = express();
const PORT = 3000;

app.use(bodyParser.json({ limit: '10mb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname)));

// Файл базы данных
const DB_FILE = path.join(__dirname, 'users.json');
let users = {};
let sessions = {}; // sessionId => phone

// Загрузка базы
function loadDB() {
  if (fs.existsSync(DB_FILE)) {
    users = JSON.parse(fs.readFileSync(DB_FILE));
  } else {
    users = {};
  }
}
function saveDB() {
  fs.writeFileSync(DB_FILE, JSON.stringify(users, null, 2));
}
loadDB();

// Генерация ID
function genId(len = 16) {
  return crypto.randomBytes(len).toString('hex');
}

// Middleware для проверки сессии
function authMiddleware(req, res, next) {
  const sid = req.cookies['sid'];
  if (!sid || !sessions[sid]) return res.status(401).json({ error: 'Не авторизован' });
  req.user = users[sessions[sid]];
  req.phone = sessions[sid];
  next();
}

// Регистрация
app.post('/api/register', (req, res) => {
  const { fio, dob, gender, email, phone, password, cardNumber, cardType } = req.body;
  if (!fio || !email || !phone || !password) return res.status(400).json({ error: 'Незаполнены обязательные поля' });
  if (users[phone]) return res.status(400).json({ error: 'Пользователь с таким телефоном уже существует' });

  users[phone] = {
    id: genId(),
    fio, dob, gender, email, phone,
    password, cardNumber: cardNumber||'', cardType: cardType||'Classic',
    avatar: '', bonusMiles: 0, orders: [], cart: []
  };
  saveDB();
  // создаём сессию
  const sid = genId();
  sessions[sid] = phone;
  res.cookie('sid', sid, { httpOnly: true });
  res.json({ success: true });
});

// Вход
app.post('/api/login', (req, res) => {
  const { phone, password } = req.body;
  if (!phone || !password) return res.status(400).json({ error: 'Введите телефон и пароль' });
  const u = users[phone];
  if (!u || u.password !== password) return res.status(400).json({ error: 'Неверный телефон или пароль' });
  const sid = genId();
  sessions[sid] = phone;
  res.cookie('sid', sid, { httpOnly: true });
  res.json({ success: true });
});

// Профиль
app.get('/api/profile', authMiddleware, (req, res) => {
  const { password, ...rest } = req.user;
  res.json({ user: rest });
});
app.post('/api/profile/update', authMiddleware, (req, res) => {
  const data = req.body;
  Object.assign(req.user, data);
  saveDB();
  res.json({ success: true });
});

// Выход
app.post('/api/logout', authMiddleware, (req, res) => {
  const sid = req.cookies['sid'];
  delete sessions[sid];
  res.clearCookie('sid');
  res.json({ success: true });
});

// Корзина
app.get('/api/cart', authMiddleware, (req, res) => {
  res.json({ cart: req.user.cart || [] });
});
app.post('/api/cart/add', authMiddleware, (req, res) => {
  const { id, title, price, image, qty } = req.body;
  if (!req.user.cart) req.user.cart = [];
  const existing = req.user.cart.find(x=>x.id===id);
  if (existing) existing.qty += qty||1;
  else req.user.cart.push({ id, title, price, image, qty: qty||1 });
  saveDB();
  res.json({ success: true });
});
app.post('/api/cart/remove', authMiddleware, (req, res) => {
  const { id } = req.body;
  if (!req.user.cart) req.user.cart = [];
  req.user.cart = req.user.cart.filter(x=>x.id!==id);
  saveDB();
  res.json({ success: true });
});
app.post('/api/cart/clear', authMiddleware, (req, res) => {
  req.user.cart = [];
  saveDB();
  res.json({ success: true });
});

// Checkout
app.post('/api/cart/checkout', authMiddleware, (req, res) => {
  const cart = req.user.cart || [];
  if (!cart.length) return res.status(400).json({ error: 'Корзина пуста' });
  const total = cart.reduce((sum,i)=>sum + (i.price||0)*(i.qty||1),0);
  const order = {
    id: genId(8),
    items: cart,
    total,
    createdAt: Date.now(),
    status: 'Принят'
  };
  req.user.orders.push(order);
  req.user.cart = [];
  // начисляем мили: 1 миля за 10 рублей
  req.user.bonusMiles = (req.user.bonusMiles||0) + Math.floor(total/10);
  saveDB();
  res.json({ success: true, order });
});

app.listen(PORT,()=>console.log(`Server started on http://localhost:${PORT}`));
