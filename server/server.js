import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import session from "express-session";
import MongoStore from "connect-mongo";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 10000;

// ===== Middleware =====
app.use(express.json());
app.use(cors({
  origin: process.env.CLIENT_URL || "http://localhost:3000",
  credentials: true
}));

// ===== Session =====
app.use(session({
  secret: process.env.SESSION_SECRET || "supersecret",
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.MONGO_URL,
    ttl: 60 * 60 * 24 * 7 // 7 days
  }),
  cookie: {
    secure: true,
    sameSite: "none",
    maxAge: 1000 * 60 * 60 * 24 * 7
  }
}));

// ===== Connect to Mongo =====
mongoose.connect(process.env.MONGO_URL)
  .then(() => console.log("✅ MongoDB connected"))
  .catch(err => console.error("❌ MongoDB error:", err));

// ===== User Schema =====
const userSchema = new mongoose.Schema({
  fio: String,
  email: String,
  phone: { type: String, unique: true },
  password: String,
  cardNumber: String,
  cardType: String,
  dob: String,
  gender: String,
  bonus_miles: { type: Number, default: 0 },
  status_miles: { type: Number, default: 0 }
});
const User = mongoose.model("User", userSchema);

// ===== Routes =====
app.get("/", (req, res) => res.send("✅ S7avelii Airlines API is running"));

// ---- Register ----
app.post("/api/register", async (req, res) => {
  try {
    const { fio, email, phone, password } = req.body;
    if (!fio || !email || !phone || !password)
      return res.status(400).json({ error: "Не все поля заполнены" });

    const exist = await User.findOne({ phone });
    if (exist) return res.status(400).json({ error: "Пользователь уже существует" });

    const hash = await bcrypt.hash(password, 10);
    const user = await User.create({ fio, email, phone, password: hash });

    req.session.userId = user._id;
    res.json({ message: "Регистрация успешна", user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Ошибка сервера" });
  }
});

// ---- Login ----
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

// ---- Profile ----
app.get("/api/profile", async (req, res) => {
  if (!req.session.userId)
    return res.status(401).json({ error: "Не авторизован" });

  const user = await User.findById(req.session.userId).select("-password");
  res.json(user);
});

// ---- Update Profile ----
app.post("/api/profile/update", async (req, res) => {
  if (!req.session.userId)
    return res.status(401).json({ error: "Не авторизован" });

  await User.findByIdAndUpdate(req.session.userId, req.body);
  res.json({ message: "Профиль обновлен" });
});

// ---- Logout ----
app.get("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

// ===== Start server =====
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));

