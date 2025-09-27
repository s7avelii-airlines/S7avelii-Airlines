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
      secure: true,
      sameSite: "lax",
      maxAge: 1000 * 60 * 60 * 24 * 7
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
  let users = loadUsers();
  const user = users.find((u) => u.email === email);
  if (!user) return res.status(400).json({ message: "Неверный логин или пароль" });
  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(400).json({ message: "Неверный логин или пароль" });
  req.session.userId = user.id;
  res.json({ message: "Вход успешен", user });
});

// Профиль
app.get("/api/profile", (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ message: "Не авторизован" });
  }
  let users = loadUsers();
  const user = users.find((u) => u.id === req.session.userId);
  if (!user) return res.status(401).json({ message: "Пользователь не найден" });
  res.json({ user });
});

// Обновление профиля
app.post("/api/update-profile", (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ message: "Не авторизован" });
  }
  let users = loadUsers();
  let user = users.find((u) => u.id === req.session.userId);
  if (!user) return res.status(404).json({ message: "Пользователь не найден" });

  const allowedFields = ["fio", "dob", "gender", "email", "phone", "card", "cardType", "avatar", "bonusMiles"];
  for (let f of allowedFields) {
    if (req.body[f] !== undefined) user[f] = req.body[f];
  }

  saveUsers(users);
  res.json({ message: "Профиль обновлен", user });
});

// Выход
app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("connect.sid");
    res.json({ message: "Вы вышли" });
  });
});

// ===== Админ =====
function isAdmin(req, res, next) {
  let users = loadUsers();
  const user = users.find((u) => u.id === req.session.userId);
  if (!user || user.role !== "admin") {
    return res.status(403).json({ message: "Нет доступа" });
  }
  next();
}

app.get("/api/admin/users", isAdmin, (req, res) => {
  const users = loadUsers();
  res.json(users.map(u => ({ ...u, password: undefined })));
});

app.delete("/api/admin/users/:id", isAdmin, (req, res) => {
  let users = loadUsers();
  users = users.filter(u => u.id !== req.params.id);
  saveUsers(users);
  res.json({ message: "Пользователь удален" });
});

app.patch("/api/admin/users/:id", isAdmin, (req, res) => {
  let users = loadUsers();
  const user = users.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ message: "Пользователь не найден" });

  const allowed = ["fio", "dob", "gender", "email", "phone", "card", "cardType", "bonusMiles", "role"];
  for (let f of allowed) {
    if (req.body[f] !== undefined) user[f] = req.body[f];
  }
  saveUsers(users);
  res.json({ message: "Пользователь обновлен", user });
});

// ===== Статика =====
app.use(express.static(path.join(__dirname, "public")));

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

