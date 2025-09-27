// server.js
import express from "express";
import fs from "fs";
import path from "path";
import bodyParser from "body-parser";
import cookieParser from "cookie-parser";

const app = express();
const PORT = 3000;

// путь к файлу с пользователями
const DB_FILE = path.join(process.cwd(), "users.json");

// читаем пользователей из файла или создаём пустой массив
let users = [];
if (fs.existsSync(DB_FILE)) {
  try {
    users = JSON.parse(fs.readFileSync(DB_FILE));
  } catch {
    users = [];
  }
}

// сохраняем пользователей в файл
function saveUsers() {
  fs.writeFileSync(DB_FILE, JSON.stringify(users, null, 2));
}

app.use(bodyParser.json());
app.use(cookieParser());

// =================== API ===================

// Регистрация
app.post("/api/register", (req, res) => {
  const { fio, phone, email, password, cardType } = req.body;

  if (!fio || !phone || !email || !password) {
    return res.json({ ok: false, error: "Все обязательные поля должны быть заполнены" });
  }

  // проверка уникальности
  if (users.find(u => u.phone === phone || u.email === email)) {
    return res.json({ ok: false, error: "Пользователь с таким телефоном или email уже существует" });
  }

  const newUser = {
    fio,
    phone,
    email,
    password, // ⚠️ лучше хранить хэши, но для простоты — plain text
    cardType: cardType || "Classic",
    miles: 0,
    createdAt: new Date().toISOString()
  };

  users.push(newUser);
  saveUsers();

  res.json({ ok: true, message: "Регистрация успешна" });
});

// Вход
app.post("/api/login", (req, res) => {
  const { phone, password } = req.body;

  const user = users.find(u => u.phone === phone && u.password === password);
  if (!user) {
    return res.json({ ok: false, error: "Неверный телефон или пароль" });
  }

  res.cookie("userPhone", user.phone, { httpOnly: true });
  res.json({ ok: true, message: "Вход выполнен" });
});

// Профиль
app.get("/api/profile", (req, res) => {
  const phone = req.cookies.userPhone;
  if (!phone) return res.json({ ok: false, error: "Не авторизован" });

  const user = users.find(u => u.phone === phone);
  if (!user) return res.json({ ok: false, error: "Пользователь не найден" });

  res.json({ ok: true, profile: user });
});

// Выход
app.post("/api/logout", (req, res) => {
  res.clearCookie("userPhone");
  res.json({ ok: true, message: "Вы вышли из системы" });
});

// ==========================================

// статика для фронта (если кладёшь html/css/js в папку public)
app.use(express.static("public"));

// старт сервера
app.listen(PORT, () => {
  console.log(`✅ Сервер запущен: http://localhost:${PORT}`);
});
