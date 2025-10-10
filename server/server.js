import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import session from "express-session";
import MongoStore from "connect-mongo";

dotenv.config();
const app = express();

// ==== Настройки CORS ====
app.use(cors({
  origin: "https://www.s7avelii-airlines.ru", // ⚠️ замени на свой статичный домен
  credentials: true
}));

app.use(express.json());

// ==== Сессии ====
app.use(session({
  secret: process.env.SESSION_SECRET || "supersecret",
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ mongoUrl: process.env.MONGO_URL }),
  cookie: { secure: true, sameSite: "none", maxAge: 1000 * 60 * 60 * 24 * 7 }
}));

// ==== Подключение к Mongo ====
mongoose.connect(process.env.MONGO_URL)
  .then(() => console.log("✅ Подключено к MongoDB"))
  .catch(err => console.error("❌ Ошибка Mongo:", err));

// ==== Модель пользователя ====
const userSchema = new mongoose.Schema({
  fio: String,
  email: String,
  phone: { type: String, unique: true },
  password: String,
  cardNumber: String,
  cardType: String,
  dob: String,
  gender: String
});
const User = mongoose.model("User", userSchema);

// ==== Тестовый маршрут ====
app.get("/", (req, res) => res.send("Server OK ✅"));

// ==== Регистрация ====
app.post("/api/register", async (req, res) => {
  try {
    const { fio, email, phone, password, cardNumber, cardType, dob, gender } = req.body;
    if (!fio || !email || !phone || !password)
      return res.status(400).json({ error: "Не все поля заполнены" });

    const exist = await User.findOne({ phone });
    if (exist) return res.status(400).json({ error: "Пользователь уже существует" });

    const hash = await bcrypt.hash(password, 10);
    const user = await User.create({ fio, email, phone, password: hash, cardNumber, cardType, dob, gender });
    req.session.userId = user._id;
    res.json({ message: "Регистрация успешна", user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Ошибка сервера" });
  }
});

// ==== Авторизация ====
app.post("/api/login", async (req, res) => {
  try {
    const { phone, password } = req.body;
    const user = await User.findOne({ phone });
    if (!user) return res.status(400).json({ error: "Пользователь не найден" });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(400).json({ error: "Неверный пароль" });

    req.session.userId = user._id;
    res.json({ message: "Успешный вход", user });
  } catch (err) {
    res.status(500).json({ error: "Ошибка сервера" });
  }
});

// ==== Профиль ====
app.get("/api/profile", async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: "Не авторизован" });
  const user = await User.findById(req.session.userId).select("-password");
  res.json(user);
});

// ==== Выход ====
app.get("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

// ==== Запуск ====
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`🚀 Сервер запущен на порту ${PORT}`));
