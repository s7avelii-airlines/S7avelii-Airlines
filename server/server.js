import express from "express";
import mongoose from "mongoose";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import session from "express-session";
import MongoStore from "connect-mongo";
import cors from "cors";

dotenv.config();
const app = express();

/* ===================== CONFIG ===================== */
const FRONTEND_URL = "https://www.s7avelii-airlines.ru"; // 👈 твой домен
const PORT = process.env.PORT || 10000;

/* ===================== MIDDLEWARE ===================== */
app.use(cors({
  origin: FRONTEND_URL,
  credentials: true
}));
app.use(express.json());

app.use(session({
  secret: process.env.SESSION_SECRET || "supersecret",
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.MONGO_URL,
    ttl: 7 * 24 * 60 * 60 // 7 дней
  }),
  cookie: {
    secure: true,
    sameSite: "none",
    httpOnly: true,
    maxAge: 1000 * 60 * 60 * 24 * 7
  }
}));

/* ===================== MONGODB ===================== */
mongoose.connect(process.env.MONGO_URL)
  .then(() => console.log("✅ Подключено к MongoDB"))
  .catch(err => console.error("❌ Ошибка Mongo:", err));

/* ===================== SCHEMAS ===================== */
const userSchema = new mongoose.Schema({
  fio: String,
  email: String,
  phone: { type: String, unique: true },
  password: String,
  cardNumber: String,
  cardType: String,
  dob: String,
  gender: String,
  avatar: String,
  bonus_miles: { type: Number, default: 0 },
  status_miles: { type: Number, default: 0 },
  vk: String,
  telegram: String
});

const User = mongoose.model("User", userSchema);

/* ===================== ROUTES ===================== */

// Проверка сервера
app.get("/", (req, res) => res.send("✅ Сервер работает"));

// Регистрация
app.post("/api/register", async (req, res) => {
  try {
    const { fio, email, phone, password, cardNumber, cardType, dob, gender } = req.body;
    if (!fio || !email || !phone || !password)
      return res.status(400).json({ error: "Не все поля заполнены" });

    const exists = await User.findOne({ phone });
    if (exists) return res.status(400).json({ error: "Пользователь уже существует" });

    const hash = await bcrypt.hash(password, 10);
    const user = await User.create({ fio, email, phone, password: hash, cardNumber, cardType, dob, gender });
    req.session.userId = user._id;

    res.json({ message: "Регистрация успешна", user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Ошибка сервера" });
  }
});

// Авторизация
app.post("/api/login", async (req, res) => {
  try {
    const { phone, password } = req.body;
    const user = await User.findOne({ phone });
    if (!user) return res.status(400).json({ error: "Пользователь не найден" });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ error: "Неверный пароль" });

    req.session.userId = user._id;
    res.json({ message: "Успешный вход", user });
  } catch (err) {
    res.status(500).json({ error: "Ошибка сервера" });
  }
});

// Профиль
app.get("/api/profile", async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: "Не авторизован" });
  const user = await User.findById(req.session.userId).select("-password");
  res.json(user);
});

// Обновление профиля
app.post("/api/profile/update", async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: "Не авторизован" });
  try {
    const updates = req.body;
    if (updates.password)
      updates.password = await bcrypt.hash(updates.password, 10);
    await User.findByIdAndUpdate(req.session.userId, updates);
    res.json({ message: "Профиль обновлён" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Ошибка обновления профиля" });
  }
});

// Выход
app.get("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

/* ===================== SERVER START ===================== */
app.listen(PORT, () => {
  console.log(`🚀 Сервер запущен на порту ${PORT}`);
});
