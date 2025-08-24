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

// ✅ Подключение к PostgreSQL (только через DATABASE_URL)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Проверка соединения
(async () => {
  try {
    const client = await pool.connect();
    console.log("✅ Подключение к базе данных установлено");

    const res = await client.query("SELECT NOW()");
    console.log("⏰ Время в БД:", res.rows[0]);

    client.release();
  } catch (err) {
    console.error("❌ Ошибка подключения:", err);
  }
})();

// 🔹 Тестовый маршрут
app.get("/", (req, res) => {
  res.send("🚀 Сервер работает!");
});

// 🔹 Регистрация
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: "Заполните все поля" });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query(
      "INSERT INTO users (username, password) VALUES ($1, $2)",
      [username, hashedPassword]
    );
    res.json({ message: "✅ Пользователь зарегистрирован" });
  } catch (err) {
    console.error(err);
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
      { id: user.id },
      process.env.JWT_SECRET || "secret",
      { expiresIn: "1h" }
    );

    res.json({ message: "✅ Успешный вход", token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Ошибка входа" });
  }
});

// 🔹 Запуск сервера
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Сервер запущен на порту ${PORT}`);
});
