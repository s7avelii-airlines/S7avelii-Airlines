// server.js
require("dotenv").config();
const express = require("express");
const { Pool } = require("pg");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
app.use(cors());
app.use(express.json());

// Подключение к PostgreSQL (Render требует SSL)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    require: true,
    rejectUnauthorized: false, // важно для Render
  },
});

// Проверка соединения при старте
(async () => {
  try {
    console.log("⏳ Подключение к базе...");
    const client = await pool.connect();
    console.log("✅ Подключение к базе данных установлено");

    const res = await client.query("SELECT NOW()");
    console.log("⏰ Время в БД:", res.rows[0]);

    client.release();
  } catch (err) {
    console.error("❌ Ошибка подключения к БД при старте:", err.message);
  }
})();

// Middleware для проверки токена
function authMiddleware(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) return res.status(401).json({ error: "Нет токена" });

  jwt.verify(token, process.env.JWT_SECRET || "secret", (err, user) => {
    if (err) return res.status(403).json({ error: "Неверный токен" });
    req.user = user;
    next();
  });
}

// 🔹 Тестовый маршрут
app.get("/", (req, res) => {
  res.send("🚀 Сервер работает!");
});

// 🔹 Регистрация
app.post("/register", async (req, res) => {
  const { username, password, email, phone } = req.body;
  if (!username || !password || !email || !phone) {
    return res.status(400).json({ error: "Заполните все поля" });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query(
      "INSERT INTO users (username, password, email, phone) VALUES ($1, $2, $3, $4)",
      [username, hashedPassword, email, phone]
    );
    res.json({ message: "✅ Пользователь зарегистрирован" });
  } catch (err) {
    console.error("❌ Ошибка регистрации:", err.message);
    res.status(500).json({ error: "Ошибка регистрации" });
  }
});

// 🔹 Авторизация
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    const result = await pool.query("SELECT * FROM users WHERE username = $1", [username]);
    const user = result.rows[0];

    if (!user) return res.status(400).json({ error: "Пользователь не найден" });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ error: "Неверный пароль" });

    const token = jwt.sign(
      { id: user.id, username: user.username },
      process.env.JWT_SECRET || "secret",
      { expiresIn: "1h" }
    );

    res.json({ message: "✅ Успешный вход", token });
  } catch (err) {
    console.error("❌ Ошибка входа:", err.message);
    res.status(500).json({ error: "Ошибка входа" });
  }
});

// 🔹 Пример защищённого маршрута
app.get("/profile", authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, username, email, phone, created_at FROM users WHERE id = $1",
      [req.user.id]
    );
    res.json(result.rows[0]);
  } catch (err) {
    console.error("❌ Ошибка получения профиля:", err.message);
    res.status(500).json({ error: "Ошибка получения профиля" });
  }
});

// 🔹 Запуск сервера
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Сервер запущен на порту ${PORT}`);
});
