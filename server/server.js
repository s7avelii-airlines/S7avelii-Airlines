import express from "express";
import path from "path";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import session from "express-session";
import cookieParser from "cookie-parser";
import pkg from "pg";

dotenv.config();
const { Pool } = pkg;

const app = express();
const PORT = process.env.PORT || 3000;
const __dirname = path.resolve();

// ==== Подключение к базе ====
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false } // важно для Render
});

// ==== Middleware ====
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(
  session({
    secret: process.env.SESSION_SECRET || "supersecret",
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 1000 * 60 * 60 * 24 * 7 }
  })
);

// ==== Статика ====
const PUBLIC_DIR = path.join(__dirname, "public");
app.use(express.static(PUBLIC_DIR));

// ==== Инициализация таблиц ====
async function initDB() {
  try {
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
    console.log("✅ Таблицы инициализированы");
  } catch (e) {
    console.error("Ошибка инициализации БД:", e);
  }
}
initDB();

// ==== Тест подключения к БД ====
app.get("/api/testdb", async (req, res) => {
  try {
    const { rows } = await pool.query("SELECT NOW() AS now");
    res.json({ ok: true, server_time: rows[0].now });
  } catch (e) {
    console.error("Ошибка подключения к БД:", e);
    res.status(500).json({ ok: false, error: "Не удалось подключиться к базе" });
  }
});

// ==== Регистрация ====
app.post("/api/register", async (req, res) => {
  try {
    const { fio, phone, email, password, card_number, card_type } = req.body;
    if (!phone || !password) return res.status(400).json({ error: "Телефон и пароль обязательны" });
    const hash = await bcrypt.hash(password, 10);
    const { rows } = await pool.query(
      "INSERT INTO users (fio, phone, email, password, card_number, card_type) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *",
      [fio, phone, email, hash, card_number, card_type]
    );
    req.session.userId = rows[0].id;
    res.json(rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Ошибка регистрации" });
  }
});

// ==== Логин ====
app.post("/api/login", async (req, res) => {
  try {
    const { phone, password } = req.body;
    const { rows } = await pool.query("SELECT * FROM users WHERE phone=$1", [phone]);
    const user = rows[0];
    if (!user) return res.status(400).json({ error: "Пользователь не найден" });
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(400).json({ error: "Неверный пароль" });
    req.session.userId = user.id;
    res.json(user);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Ошибка логина" });
  }
});

// ==== Профиль ====
app.get("/api/profile", async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: "Не авторизован" });
  const { rows } = await pool.query("SELECT * FROM users WHERE id=$1", [req.session.userId]);
  res.json(rows[0]);
});

// ==== SPA fallback ====
app.get("*", (req, res) => res.sendFile(path.join(PUBLIC_DIR, "index.html")));

// ==== Запуск сервера ====
app.listen(PORT, () => console.log(`✅ Сервер запущен на порту ${PORT}`));

