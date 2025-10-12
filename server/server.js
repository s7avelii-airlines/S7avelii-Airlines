import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || "super_secret_key";

// ====== MONGO CONNECTION ======
mongoose
  .connect(process.env.MONGO_URL, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => console.error("❌ Mongo error:", err.message));

// ====== MIDDLEWARE ======
app.use(cors({ origin: "*", credentials: true }));
app.use(express.json());
app.use(express.static("public"));

// ====== USER MODEL ======
const userSchema = new mongoose.Schema({
  fio: { type: String, required: true },
  email: { type: String, unique: true, required: true },
  phone: { type: String },
  password: { type: String, required: true },
  avatar: { type: String, default: "" },
  dob: { type: String, default: "" },
  gender: { type: String, default: "" },
  cardNumber: { type: String, default: "" },
  cardType: { type: String, default: "" },
  bonusMiles: { type: Number, default: 0 },
  statusMiles: { type: Number, default: 0 },
});

const User = mongoose.model("User", userSchema);

// ====== HELPER ======
function createToken(id) {
  return jwt.sign({ id }, JWT_SECRET, { expiresIn: "30d" });
}

async function authMiddleware(req, res, next) {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ message: "Нет токена" });

    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = await User.findById(decoded.id).select("-password");
    if (!req.user) return res.status(404).json({ message: "Пользователь не найден" });
    next();
  } catch (err) {
    res.status(401).json({ message: "Ошибка авторизации" });
  }
}

// ====== ROUTES ======

// Health check
app.get("/", (req, res) => {
  res.send("✅ S7avelii Airlines сервер работает!");
});

// -------- AUTH --------

// Register
app.post("/api/register", async (req, res) => {
  try {
    const { fio, email, password, phone } = req.body;
    if (!fio || !email || !password) {
      return res.status(400).json({ message: "Введите ФИО, email и пароль" });
    }

    const exist = await User.findOne({ email });
    if (exist) return res.status(400).json({ message: "Такой пользователь уже существует" });

    const hash = await bcrypt.hash(password, 10);
    const newUser = await User.create({ fio, email, password: hash, phone });

    const token = createToken(newUser._id);
    res.json({ token, user: { ...newUser._doc, password: undefined } });
  } catch (err) {
    res.status(500).json({ message: "Ошибка регистрации", error: err.message });
  }
});

// Login
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "Пользователь не найден" });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ message: "Неверный пароль" });

    const token = createToken(user._id);
    res.json({ token, user: { ...user._doc, password: undefined } });
  } catch (err) {
    res.status(500).json({ message: "Ошибка входа", error: err.message });
  }
});

// -------- PROFILE --------

// Get profile
app.get("/api/profile", authMiddleware, async (req, res) => {
  res.json({ user: req.user });
});

// Update profile
app.put("/api/profile", authMiddleware, async (req, res) => {
  try {
    const update = req.body;
    const updated = await User.findByIdAndUpdate(req.user._id, update, { new: true }).select("-password");
    res.json({ user: updated });
  } catch (err) {
    res.status(500).json({ message: "Ошибка изменения профиля", error: err.message });
  }
});

// -------- PRODUCTS --------

const productSchema = new mongoose.Schema({
  name: String,
  price: Number,
});

const Product = mongoose.model("Product", productSchema);

app.get("/api/shop", async (req, res) => {
  const items = await Product.find();
  res.json({ products: items });
});

app.post("/api/checkout", authMiddleware, async (req, res) => {
  // Можно добавить логику создания заказов
  res.json({ message: "Заказ успешно оформлен" });
});

// ====== START ======
app.listen(PORT, () => console.log(`🚀 Сервер запущен на порту ${PORT}`));
