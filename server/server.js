// ==== Импорты ====
import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import session from "express-session";
import MongoStore from "connect-mongo";

// ==== Настройка ====
dotenv.config();
const app = express();
app.use(express.json());

// ==== CORS ====
app.use(cors({
  origin: [
    "https://s7avelii-airlines.ru",
    "https://www.s7avelii-airlines.ru"
  ],
  credentials: true
}));

// ==== Сессии ====
app.use(session({
  secret: process.env.SESSION_SECRET || "supersecret",
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.MONGO_URL,
    ttl: 60 * 60 * 24 * 7 // 7 дней
  }),
  cookie: {
    secure: true,          // обязательно для HTTPS
    sameSite: "none",      // нужно для CORS
    httpOnly: true,
    maxAge: 1000 * 60 * 60 * 24 * 7
  }
}));

// ==== Подключение к Mongo ====
mongoose.connect(process.env.MONGO_URL)
  .then(() => console.log("✅ MongoDB подключен"))
  .catch(err => console.error("❌ Ошибка MongoDB:", err));

// ==== Модель пользователя ====
const userSchema = new mongoose.Schema({
  fio: String,
  email: String,
  phone: { type: String, unique: true },
  password: String,
  dob: String,
  gender: String,
  cardNumber: String,
  cardType: String,
  avatar: String,
}, { timestamps: true });

const User = mongoose.model("User", userSchema);

// ==== Тестовый маршрут ====
app.get("/", (req, res) => res.send("✅ S7avelii Airlines Server работает!"));

// ==== Регистрация ====
app.post("/api/register", async (req, res) => {
  try {
    const { fio, email, phone, password, dob, gender, cardNumber, cardType } = req.body;

    if (!fio || !email || !phone || !password) {
      return res.status(400).json({ error: "Все обязательные поля должны быть заполнены" });
    }

    const exist = await User.findOne({ phone });
    if (exist) {
      return res.status(400).json({ error: "Пользователь с таким номером уже существует" });
    }

    const hash = await bcrypt.hash(password, 10);
    const user = await User.create({
      fio, email, phone, password: hash, dob, gender, cardNumber, cardType
    });

    req.session.userId = user._id;
    res.json({ message: "Регистрация успешна", userId: user._id });

  } catch (err) {
    console.error("❌ Ошибка регистрации:", err);
    res.status(500).json({ error: "Ошибка сервера при регистрации" });
  }
});

// ==== Авторизация ====
app.post("/api/login", async (req, res) => {
  try {
    const { phone, password } = req.body;
    const user = await User.findOne({ phone });
    if (!user) return res.status(400).json({ error: "Пользователь не найден" });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ error: "Неверный пароль" });

    req.session.userId = user._id;
    res.json({ message: "Успешный вход", userId: user._id });
  } catch (err) {
    console.error("Ошибка входа:", err);
    res.status(500).json({ error: "Ошибка сервера при входе" });
  }
});

// ==== Получить профиль ====
app.get("/api/profile", async (req, res) => {
  try {
    if (!req.session.userId)
      return res.status(401).json({ error: "Не авторизован" });

    const user = await User.findById(req.session.userId).select("-password");
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: "Ошибка при получении профиля" });
  }
});

// ==== Обновление профиля ====
app.post("/api/profile/update", async (req, res) => {
  try {
    if (!req.session.userId)
      return res.status(401).json({ error: "Не авторизован" });

    await User.findByIdAndUpdate(req.session.userId, req.body);
    res.json({ message: "Профиль обновлён" });
  } catch (err) {
    res.status(500).json({ error: "Ошибка обновления профиля" });
  }
});

// ==== Выход ====
app.get("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

// ==== Защита от ошибок ====
app.use((err, req, res, next) => {
  console.error("Ошибка:", err);
  res.status(500).json({ error: "Ошибка сервера" });
});

// ==== Запуск ====
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`🚀 Сервер запущен на порту ${PORT}`));
