// server.js
import express from 'express';
import session from 'express-session';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';

const app = express();
const PORT = process.env.PORT || 3000;
const USERS_FILE = path.resolve('./users.json');

app.use(express.json());
app.set('trust proxy', 1); // важно для продакшн (за прокси)

app.use(session({
  name: 's7avelii.sid',
  secret: process.env.SESSION_SECRET || 'change-me',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production', // требует HTTPS
    sameSite: 'lax',
    maxAge: 1000 * 60 * 60 * 24 * 7 // 7 дней
  }
}));

// ----- HELPERS -----
function loadUsers() {
  try {
    const data = fs.readFileSync(USERS_FILE, 'utf-8');
    return JSON.parse(data || '[]');
  } catch (e) {
    return [];
  }
}

function saveUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

function findUserByPhone(phone) {
  const users = loadUsers();
  return users.find(u => u.phone === phone);
}

function findUserById(id) {
  const users = loadUsers();
  return users.find(u => u.id === id);
}

// ----- API -----
// регистрация
app.post('/api/register', (req, res) => {
  const { fio, dob, gender, email, phone, password, cardNumber, cardType } = req.body;
  if (!fio || !email || !phone || !password) {
    return res.status(400).json({ error: 'Обязательные поля не заполнены' });
  }
  const users = loadUsers();
  if (users.some(u => u.phone === phone)) return res.status(400).json({ error: 'Телефон уже зарегистрирован' });

  const id = crypto.randomUUID();
  const newUser = {
    id, fio, dob, gender, email, phone,
    password: hashPassword(password),
    cardNumber, cardType,
    bonusMiles: 0,
    orders: [],
    cart: [],
    avatar: ''
  };
  users.push(newUser);
  saveUsers(users);

  req.session.userId = id; // логиним сразу
  res.json({ message: 'Регистрация успешна', user: newUser });
});

// логин
app.post('/api/login', (req, res) => {
  const { phone, password } = req.body;
  if (!phone || !password) return res.status(400).json({ error: 'Телефон и пароль обязательны' });

  const user = findUserByPhone(phone);
  if (!user || user.password !== hashPassword(password)) return res.status(401).json({ error: 'Неверные данные' });

  req.session.userId = user.id;
  res.json({ message: 'Вход успешен', user });
});

// логаут
app.post('/api/logout', (req, res) => {
  req.session.destroy(err => {
    res.json({ message: 'Вышли' });
  });
});

// профиль
app.get('/api/profile', (req, res) => {
  const user = findUserById(req.session.userId);
  if (!user) return res.status(401).json({ error: 'Не авторизован' });
  res.json({ user });
});

// обновление профиля
app.post('/api/profile/update', (req, res) => {
  const user = findUserById(req.session.userId);
  if (!user) return res.status(401).json({ error: 'Не авторизован' });

  const allowed = ['fio','dob','gender','email','phone','cardNumber','cardType','avatar','password'];
  allowed.forEach(k => {
    if (req.body[k] !== undefined) {
      user[k] = k === 'password' ? hashPassword(req.body[k]) : req.body[k];
    }
  });

  const users = loadUsers().map(u => u.id === user.id ? user : u);
  saveUsers(users);
  res.json({ message: 'Обновлено', user });
});

// ----- CART -----
app.get('/api/cart', (req, res) => {
  const user = findUserById(req.session.userId);
  if (!user) return res.status(401).json({ error: 'Не авторизован' });
  res.json({ cart: user.cart || [] });
});

app.post('/api/cart/add', (req, res) => {
  const user = findUserById(req.session.userId);
  if (!user) return res.status(401).json({ error: 'Не авторизован' });
  const item = req.body;
  if (!item.id || !item.title || !item.price) return res.status(400).json({ error: 'Некорректный товар' });

  user.cart = user.cart || [];
  const exist = user.cart.find(i => i.id === item.id);
  if (exist) exist.qty = (exist.qty||1)+1;
  else user.cart.push({ ...item, qty: 1 });

  const users = loadUsers().map(u => u.id === user.id ? user : u);
  saveUsers(users);
  res.json({ message: 'Добавлено в корзину' });
});

app.post('/api/cart/remove', (req, res) => {
  const user = findUserById(req.session.userId);
  if (!user) return res.status(401).json({ error: 'Не авторизован' });
  const { id } = req.body;
  user.cart = (user.cart||[]).filter(i => i.id !== id);
  const users = loadUsers().map(u => u.id === user.id ? user : u);
  saveUsers(users);
  res.json({ message: 'Удалено' });
});

app.post('/api/cart/clear', (req, res) => {
  const user = findUserById(req.session.userId);
  if (!user) return res.status(401).json({ error: 'Не авторизован' });
  user.cart = [];
  const users = loadUsers().map(u => u.id === user.id ? user : u);
  saveUsers(users);
  res.json({ message: 'Корзина очищена' });
});

// checkout - создаём заказ
app.post('/api/cart/checkout', (req, res) => {
  const user = findUserById(req.session.userId);
  if (!user) return res.status(401).json({ error: 'Не авторизован' });
  if (!user.cart || !user.cart.length) return res.status(400).json({ error: 'Корзина пуста' });

  const orderId = crypto.randomUUID();
  const total = user.cart.reduce((a,i)=>a+(parseFloat((i.price||'0').toString().replace(/[^\d.-]/g,''))||0)*(i.qty||1),0);
  const newOrder = {
    id: orderId,
    createdAt: new Date(),
    items: user.cart,
    total,
    status: 'Принят'
  };
  user.orders = user.orders||[];
  user.orders.push(newOrder);

  user.cart = []; // очистка корзины
  const users = loadUsers().map(u => u.id === user.id ? user : u);
  saveUsers(users);

  res.json({ message: 'Заказ создан', order: newOrder });
});

// ----- STATIC -----
app.use(express.static(path.join(process.cwd(), 'public'))); // тут лежат auth.html, cabinet.html и все ресурсы

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
