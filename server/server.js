import express from "express";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import session from "express-session";
import pkg from "pg";

dotenv.config();
const { Pool } = pkg;

const app = express();
const PORT = process.env.PORT || 3000;

// ==== Подключение к базе ====
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ==== Middleware ====
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || "supersecret",
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000*60*60*24 }
}));

// ==== Инициализация таблицы пользователей ====
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      fio TEXT,
      phone TEXT UNIQUE,
      email TEXT,
      password TEXT,
      card_number TEXT,
      card_type TEXT
    );
  `);
}
initDB();

// ==== Тест подключения к базе ====
app.get("/api/testdb", async (req, res) => {
  try {
    const { rows } = await pool.query("SELECT 1 + 1 AS result");
    res.json({ ok: true, result: rows[0].result });
  } catch (e) {
    console.error("DB Test Error:", e);
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ==== Регистрация ====
app.post("/api/register", async (req, res) => {
  try {
    const { fio, phone, email, password, card_number, card_type } = req.body;
    if (!phone || !password) return res.status(400).json({ error: "Введите телефон и пароль" });
    const hash = await bcrypt.hash(password, 10);
    const { rows } = await pool.query(
      "INSERT INTO users (fio, phone, email, password, card_number, card_type) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *",
      [fio, phone, email, hash, card_number, card_type]
    );
    req.session.userId = rows[0].id;
    res.json({ ok: true, user: rows[0] });
  } catch (e) {
    console.error("Register Error:", e);
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ==== Логин ====
app.post("/api/login", async (req, res) => {
  try {
    const { phone, password } = req.body;
    const { rows } = await pool.query("SELECT * FROM users WHERE phone=$1", [phone]);
    const user = rows[0];
    if (!user) return res.status(400).json({ ok: false, error: "Пользователь не найден" });
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ ok: false, error: "Неверный пароль" });
    req.session.userId = user.id;
    res.json({ ok: true, user });
  } catch (e) {
    console.error("Login Error:", e);
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ==== Профиль ====
app.get("/api/profile", async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ ok: false, error: "Не авторизован" });
  const { rows } = await pool.query("SELECT * FROM users WHERE id=$1", [req.session.userId]);
  res.json({ ok: true, user: rows[0] });
});

// ==== Запуск сервера ====
app.listen(PORT, () => console.log(`✅ Server started on port ${PORT}`));
