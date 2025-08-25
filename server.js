// server.js
require("dotenv").config();
const path = require("path");
const express = require("express");
const { Pool } = require("pg");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
app.use(cors());
app.use(express.json());

// Настройка DB (Render/Prod: ssl.rejectUnauthorized = false)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false
});

// Проверка соединения (не критично — просто лог)
(async () => {
  try {
    const client = await pool.connect();
    console.log("✅ Подключение к базе данных установлено");
    const r = await client.query("SELECT NOW()");
    console.log("⏰ DB time:", r.rows[0]);
    client.release();
  } catch (err) {
    console.error("❌ Ошибка подключения к БД при старте:", err.message || err);
  }
})();

// ----------------- API (пример) -----------------
app.post("/register", async (req, res) => {
  const { username, password, email, phone } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Заполните username и password" });

  try {
    const hash = await bcrypt.hash(password, 10);
    await pool.query(
      "INSERT INTO users (username, password, email, phone) VALUES ($1,$2,$3,$4)",
      [username, hash, email || null, phone || null]
    );
    res.json({ ok: true });
  } catch (err) {
    console.error("register error:", err.message || err);
    res.status(500).json({ error: "Ошибка регистрации" });
  }
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await pool.query("SELECT * FROM users WHERE username = $1", [username]);
    const user = result.rows[0];
    if (!user) return res.status(400).json({ error: "Пользователь не найден" });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ error: "Неверный пароль" });

    const token = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET || "secret", { expiresIn: "1h" });
    res.json({ ok: true, token });
  } catch (err) {
    console.error("login error:", err.message || err);
    res.status(500).json({ error: "Ошибка входа" });
  }
});
// -------------------------------------------------

// Отдаём статику из public/
const publicPath = path.join(__dirname, "public");
app.use(express.static(publicPath));

// Для любого GET-запроса возвращаем index.html (если ты хочешь SPA поведение)
app.get("*", (req, res) => {
  // если запрос к API — пусть API обрабатывает (мы выше описали API маршруты),
  // но поскольку они начинаются с /register /login и т.д., сюда попадут все прочие GET
  res.sendFile(path.join(publicPath, "index.html"));
});

// Запуск
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Сервер запущен на порту ${PORT}`));
