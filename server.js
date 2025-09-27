// server.js
import express from "express";
import fs from "fs";
import path from "path";
import session from "express-session";
import bodyParser from "body-parser";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;
const USERS_FILE = path.join(__dirname, "users.json");

// middleware
app.use(bodyParser.json());
app.use(express.static("public")); // папка с auth.html, cabinet.html, картинками

// настройка сессий (для Render + домен обязательно secure + sameSite:'none')
app.use(
  session({
    secret: process.env.SESSION_SECRET || "supersecret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: true,      // обязательно для https
      sameSite: "none",  // чтобы работало через твой домен
      maxAge: 1000 * 60 * 60 * 24 * 7, // 7 дней
    },
  })
);

// функция чтения пользователей
function readUsers() {
  if (!fs.existsSync(USERS_FILE)) return [];
  return JSON.parse(fs.readFileSync(USERS_FILE, "utf8"));
}

// функция записи пользователей
function writeUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2), "utf8");
}

// регистрация
app.post("/api/register", (req, res) => {
  const { fio, dob, gender, email, phone, card, cardType } = req.body;

  if (!fio || !email || !phone) {
    return res.status(400).json({ message: "ФИО, Email и Телефон обязательны" });
  }

  let users = readUsers();

  // проверка на дубликат
  const exists = users.find((u) => u.email === email || u.phone === phone);
  if (exists) {
    return res.status(400).json({ message: "Такой Email или Телефон уже зарегистрирован" });
  }

  const newUser = {
    id: Date.now(),
    fio,
    dob,
    gender,
    email,
    phone,
    card,
    cardType,
  };

  users.push(newUser);
  writeUsers(users);

  // создаём сессию
  req.session.userId = newUser.id;

  res.json({ message: "Регистрация успешна", user: newUser });
});

// вход
app.post("/api/login", (req, res) => {
  const { fio, phone } = req.body;

  if (!fio || !phone) {
    return res.status(400).json({ message: "Введите ФИО и телефон" });
  }

  const users = readUsers();
  const user = users.find((u) => u.fio === fio && u.phone === phone);

  if (!user) {
    return res.status(401).json({ message: "Неверные данные или пользователь не найден" });
  }

  req.session.userId = user.id;
  res.json({ message: "Вход успешен", user });
});

// получить профиль
app.get("/api/profile", (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ message: "Не авторизован" });
  }
  const users = readUsers();
  const user = users.find((u) => u.id === req.session.userId);
  if (!user) {
    return res.status(404).json({ message: "Пользователь не найден" });
  }
  res.json({ user });
});

// выход
app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("connect.sid");
    res.json({ message: "Выход выполнен" });
  });
});

// запуск
app.listen(PORT, () => {
  console.log(`✅ Сервер запущен на http://localhost:${PORT}`);
});
```
