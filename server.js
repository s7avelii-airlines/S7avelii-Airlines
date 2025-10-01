const express = require("express");
const fs = require("fs");
const path = require("path");
const cookieParser = require("cookie-parser");
const { v4: uuidv4 } = require("uuid");

const app = express();
const PORT = process.env.PORT || 3000;
const USERS_FILE = path.join(__dirname, "users.json");

// Middleware
app.use(express.json({ limit: "5mb" }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

// Загружаем пользователей
function loadUsers() {
  if (!fs.existsSync(USERS_FILE)) {
    fs.writeFileSync(USERS_FILE, JSON.stringify([]));
  }
  return JSON.parse(fs.readFileSync(USERS_FILE));
}

// Сохраняем пользователей
function saveUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

// Получить текущего юзера по сессии
function getUser(req) {
  const sid = req.cookies.session;
  if (!sid) return null;
  const users = loadUsers();
  return users.find((u) => u.session === sid);
}

// 📌 Регистрация
app.post("/api/register", (req, res) => {
  const { username, password, email } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: "Заполните все поля" });
  }
  let users = loadUsers();
  if (users.find((u) => u.username === username)) {
    return res.status(400).json({ error: "Такой пользователь уже есть" });
  }
  const session = uuidv4();
  const newUser = {
    id: uuidv4(),
    username,
    password,
    email: email || "",
    session,
    cart: []
  };
  users.push(newUser);
  saveUsers(users);
  res.cookie("session", session, { httpOnly: true, sameSite: "lax" });
  res.json({ success: true, user: newUser });
});

// 📌 Логин
app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  const users = loadUsers();
  const user = users.find(
    (u) => u.username === username && u.password === password
  );
  if (!user) return res.status(401).json({ error: "Неверные данные" });
  user.session = uuidv4();
  saveUsers(users);
  res.cookie("session", user.session, { httpOnly: true, sameSite: "lax" });
  res.json({ success: true, user });
});

// 📌 Выход
app.post("/api/logout", (req, res) => {
  const user = getUser(req);
  if (user) {
    user.session = null;
    let users = loadUsers();
    users = users.map((u) => (u.id === user.id ? user : u));
    saveUsers(users);
  }
  res.clearCookie("session");
  res.json({ success: true });
});

// 📌 Профиль
app.get("/api/profile", (req, res) => {
  const user = getUser(req);
  if (!user) return res.status(401).json({ error: "Не авторизован" });
  res.json({ user });
});

// 📌 Обновить профиль
app.post("/api/update-profile", (req, res) => {
  const user = getUser(req);
  if (!user) return res.status(401).json({ error: "Не авторизован" });

  Object.assign(user, req.body);
  let users = loadUsers();
  users = users.map((u) => (u.id === user.id ? user : u));
  saveUsers(users);
  res.json({ success: true, user });
});

// 📌 Добавить товар в корзину
app.post("/api/cart/add", (req, res) => {
  const user = getUser(req);
  if (!user) return res.status(401).json({ error: "Не авторизован" });

  const { id, title, price, image, qty } = req.body;
  const existing = user.cart.find((item) => item.id === id);
  if (existing) {
    existing.qty += qty || 1;
  } else {
    user.cart.push({ id, title, price, image, qty: qty || 1 });
  }

  let users = loadUsers();
  users = users.map((u) => (u.id === user.id ? user : u));
  saveUsers(users);
  res.json({ success: true, cart: user.cart });
});

// 📌 Получить корзину
app.get("/api/cart", (req, res) => {
  const user = getUser(req);
  if (!user) return res.status(401).json({ error: "Не авторизован" });
  res.json({ cart: user.cart });
});

// 📌 Удалить из корзины
app.post("/api/cart/remove", (req, res) => {
  const user = getUser(req);
  if (!user) return res.status(401).json({ error: "Не авторизован" });

  const { id } = req.body;
  user.cart = user.cart.filter((item) => item.id !== id);

  let users = loadUsers();
  users = users.map((u) => (u.id === user.id ? user : u));
  saveUsers(users);
  res.json({ success: true, cart: user.cart });
});

// 📌 Деплой Render требует index.html по умолчанию
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, () => console.log(`✅ Сервер запущен на порту ${PORT}`));
