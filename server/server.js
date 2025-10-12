const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const { Pool } = require("pg");

dotenv.config();
const app = express();
app.use(cors());
app.use(express.json());
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// =======================
// PostgreSQL connection
// =======================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// =======================
// Upload config
// =======================
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = path.join(__dirname, "uploads");
    if (!fs.existsSync(dir)) fs.mkdirSync(dir);
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + "-" + file.originalname);
  },
});
const upload = multer({ storage });

// =======================
// Middleware to verify JWT
// =======================
function auth(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Нет токена" });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET || "secretkey");
    next();
  } catch {
    res.status(401).json({ error: "Неверный токен" });
  }
}

// =======================
// Routes
// =======================

// Регистрация
app.post("/api/register", async (req, res) => {
  try {
    const { fio, email, phone, password } = req.body;
    if (!fio || !email || !phone || !password)
      return res.status(400).json({ error: "Заполните все поля" });

    const hashed = await bcrypt.hash(password, 10);
    const result = await pool.query(
      "INSERT INTO users (fio, email, phone, password) VALUES ($1, $2, $3, $4) RETURNING id, fio, email, phone",
      [fio, email, phone, hashed]
    );

    const user = result.rows[0];
    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET || "secretkey", { expiresIn: "7d" });
    res.json({ user, token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Ошибка регистрации" });
  }
});

// Вход
app.post("/api/login", async (req, res) => {
  try {
    const { identifier, password } = req.body;
    const result = await pool.query(
      "SELECT * FROM users WHERE email=$1 OR phone=$1",
      [identifier]
    );
    const user = result.rows[0];
    if (!user) return res.status(400).json({ error: "Пользователь не найден" });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ error: "Неверный пароль" });

    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET || "secretkey", { expiresIn: "7d" });
    res.json({ user, token });
  } catch (err) {
    res.status(500).json({ error: "Ошибка входа" });
  }
});

// Получить профиль
app.get("/api/profile", auth, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, fio, email, phone, avatar FROM users WHERE id=$1",
      [req.user.id]
    );
    res.json({ user: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: "Ошибка профиля" });
  }
});

// Обновить профиль
app.put("/api/profile", auth, upload.single("avatar"), async (req, res) => {
  try {
    const { fio, email, phone } = req.body;
    let avatar = null;

    if (req.file) {
      avatar = `/uploads/${req.file.filename}`;
      await pool.query("UPDATE users SET avatar=$1 WHERE id=$2", [avatar, req.user.id]);
    }

    await pool.query(
      "UPDATE users SET fio=$1, email=$2, phone=$3 WHERE id=$4",
      [fio, email, phone, req.user.id]
    );

    const result = await pool.query(
      "SELECT id, fio, email, phone, avatar FROM users WHERE id=$1",
      [req.user.id]
    );
    res.json({ user: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Ошибка обновления" });
  }
});

// =======================
// DB initialization (Render creates table automatically if missing)
// =======================
(async () => {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      fio TEXT,
      email TEXT UNIQUE,
      phone TEXT UNIQUE,
      password TEXT,
      avatar TEXT
    );
  `);
  console.log("✅ База готова");
})();

// =======================
// Start server
// =======================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Сервер запущен на порту ${PORT}`));
