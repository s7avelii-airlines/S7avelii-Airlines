const express = require("express");
const session = require("express-session");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcrypt");
const fs = require("fs");
const path = require("path");
const cors = require("cors");

const app = express();
const PORT = process.env.PORT || 3000;
const USERS_FILE = path.join(__dirname, "users.json");

// ===== Middleware =====
app.use(express.json({ limit: "5mb" }));
app.use(cookieParser());
app.use(cors({
  origin: true,
  credentials: true
}));

app.use(
  session({
    secret: process.env.SESSION_SECRET || "supersecret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: false, // для Render можно поставить true если HTTPS
      sameSite: "lax",
      maxAge: 1000 * 60 * 60 * 24 * 7 // 7 дней
    }
  })
);

// ===== Хранилище =====
function loadUsers() {
  if (!fs.existsSync(USERS_FILE)) return [];
  return JSON.parse(fs.readFileSync(USERS_FILE, "utf8"));
}

function saveUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2), "utf8");
}

// ===== Проверка аутентификации =====
function authRequired(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ message: "Не авторизован" });
  }
  next();
}

// ===== Маршруты =====

// Регистрация
app.post("/api/register", async (req, res) => {
  const { email, password, fio, phone } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: "Email и пароль обязательны" });
  }
  let users = loadUsers();
  if (users.find((u) => u.email === email)) {
    return res.status(400).json({ message: "Пользователь уже существует" });
  }
  const hashed = await bcrypt.hash(password, 10);
  const newUser = {
    id: Date.now().toString(),
    email,
    password: hashed,
    fio: fio || "",
    phone: phone || "",
    dob: "",
    gender: "",
    card: "",
    cardType: "Classic",
    avatar: "",
    bonusMiles: 952,
    role: "user"
  };
  users.push(newUser);
  saveUsers(users);
  req.session.userId = newUser.id;
  res.json({ message: "Регистрация успешна", user: newUser });
});

// Логин
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: "Email и пароль обязательны" });
  }
  let users = loadUsers();
  const user = users.find((u) => u.email === email);
  if (!user) return res.status(400).json({ message: "Пользователь не найден" });
  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(400).json({ message: "Неверный пароль" });
  req.session.userId = user.id;
  res.json({ message: "Вход успешен", user });
});

// Получить текущего пользователя
app.get("/api/me", authRequired, (req, res) => {
  const users = loadUsers();
  const user = users.find((u) => u.id === req.session.userId);
  res.json(user || null);
});

// Обновление профиля
app.post("/api/profile", authRequired, (req, res) => {
  const users = loadUsers();
  const user = users.find((u) => u.id === req.session.userId);
  if (!user) return res.status(404).json({ message: "Пользователь не найден" });
  const fields = ["fio", "phone", "email", "dob", "gender", "card", "cardType", "avatar"];
  fields.forEach(f => { if(req.body[f] !== undefined) user[f] = req.body[f]; });
  saveUsers(users);
  res.json({ message: "Профиль обновлен", user });
});

// Получить всех пользователей (для админа)
app.get("/api/users", authRequired, (req, res) => {
  const users = loadUsers();
  const currentUser = users.find(u => u.id === req.session.userId);
  if (!currentUser || currentUser.role !== "admin") {
    return res.status(403).json({ message: "Нет доступа" });
  }
  res.json(users);
});

// Выйти
app.post("/api/logout", authRequired, (req, res) => {
  req.session.destroy(err => {
    if (err) return res.status(500).json({ message: "Ошибка выхода" });
    res.clearCookie("connect.sid");
    res.json({ message: "Выход выполнен" });
  });
});

// ===== Статика =====
app.use(express.static(path.join(__dirname, "public")));

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
