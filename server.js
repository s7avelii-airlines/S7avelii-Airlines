import express from "express";
import fs from "fs";
import path from "path";
import bodyParser from "body-parser";
import cookieParser from "cookie-parser";
import cors from "cors";

const app = express();
const PORT = process.env.PORT || 3000;

// ====== ФАЙЛ ПОЛЬЗОВАТЕЛЕЙ ======
const DB_FILE = path.join(process.cwd(), "users.json");
let users = fs.existsSync(DB_FILE) ? JSON.parse(fs.readFileSync(DB_FILE)) : [];

function saveUsers() {
  fs.writeFileSync(DB_FILE, JSON.stringify(users, null, 2));
}

// ====== MIDDLEWARE ======
app.use(bodyParser.json());
app.use(cookieParser());

// ⚠️ замени на адрес твоего фронта
const FRONTEND_URL = "https://мойдомен.ru";

app.use(cors({
  origin: FRONTEND_URL,
  credentials: true
}));

// ====== API ======

// Регистрация
app.post("/api/register", (req, res) => {
  const { fio, phone, email, password, cardType } = req.body;
  if (!fio || !phone || !email || !password) {
    return res.json({ ok: false, error: "Заполните все поля" });
  }
  if (users.find(u => u.phone === phone || u.email === email)) {
    return res.json({ ok: false, error: "Такой пользователь уже есть" });
  }

  const newUser = {
    fio,
    phone,
    email,
    password, // ⚠️ лучше хэшировать
    cardType: cardType || "Classic",
    miles: 0,
    createdAt: new Date().toISOString()
  };

  users.push(newUser);
  saveUsers();
  res.json({ ok: true });
});

// Логин
app.post("/api/login", (req, res) => {
  const { phone, password } = req.body;
  const user = users.find(u => u.phone === phone && u.password === password);
  if (!user) return res.json({ ok: false, error: "Неверный телефон или пароль" });

  res.cookie("sessionUser", user.phone, {
    httpOnly: true,
    secure: true,       // обязательно для HTTPS
    sameSite: "none"    // чтобы работало между доменами
  });
  res.json({ ok: true });
});

// Профиль
app.get("/api/profile", (req, res) => {
  const phone = req.cookies.sessionUser;
  if (!phone) return res.json({ ok: false, error: "Не авторизован" });
  const user = users.find(u => u.phone === phone);
  if (!user) return res.json({ ok: false, error: "Не найден" });
  res.json({ ok: true, profile: user });
});

// Выход
app.post("/api/logout", (req, res) => {
  res.clearCookie("sessionUser", {
    httpOnly: true,
    secure: true,
    sameSite: "none"
  });
  res.json({ ok: true });
});

// ====== ЗАПУСК ======
app.listen(PORT, () => {
  console.log(`✅ Сервер запущен на порту ${PORT}`);
});
