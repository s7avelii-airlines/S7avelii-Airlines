import express from "express";
import path from "path";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import session from "express-session";
import cookieParser from "cookie-parser";
import pkg from "pg";
import cors from "cors";

dotenv.config();
const { Pool } = pkg;

const app = express();
const PORT = process.env.PORT || 3000;
const __dirname = path.resolve();

// ==== CORS для статического сайта на другом домене ====
app.use(cors({
  origin: process.env.FRONTEND_URL || "*", // сюда фронтенд
  credentials: true
}));

// ==== Подключение к базе ====
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ==== Middleware ====
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(session({
  secret: process.env.SESSION_SECRET || "supersecret",
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 * 24 * 7 }
}));

// ==== Статика ====
const PUBLIC_DIR = path.join(__dirname, "public");
app.use(express.static(PUBLIC_DIR));

// ==== Инициализация таблиц ====
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      fio TEXT,
      phone TEXT UNIQUE,
      email TEXT,
      password TEXT,
      dob TEXT,
      gender TEXT,
      card_number TEXT,
      card_type TEXT
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS products (
      id SERIAL PRIMARY KEY,
      name TEXT,
      price INTEGER
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS orders (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id),
      items JSONB,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
}
initDB();

// ==== API Пользователи ====
app.post("/api/register", async (req, res) => {
  try {
    const { fio, phone, email, password, dob, gender, cardNumber, cardType } = req.body;
    if (!phone || !password) return res.status(400).json({ error: "Телефон и пароль обязательны" });
    const hash = await bcrypt.hash(password, 10);
    const { rows } = await pool.query(
      `INSERT INTO users (fio, phone, email, password, dob, gender, card_number, card_type)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
      [fio, phone, email, hash, dob, gender, cardNumber, cardType]
    );
    req.session.userId = rows[0].id;
    res.json(rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Ошибка регистрации" });
  }
});

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
    res.status(500).json({ error: "Ошибка входа" });
  }
});

app.get("/api/profile", async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: "Не авторизован" });
  const { rows } = await pool.query("SELECT * FROM users WHERE id=$1", [req.session.userId]);
  res.json(rows[0]);
});

// ==== API Тест подключения к базе ====
app.get("/api/testdb", async (req, res) => {
  try {
    const { rows } = await pool.query("SELECT NOW() AS now");
    res.json({ ok: true, server_time: rows[0].now });
  } catch (e) {
    console.error("DB connection error:", e);
    res.status(500).json({ ok: false, error: "Не удалось подключиться к базе" });
  }
});

// ==== SPA fallback ====
app.get("*", (req, res) => res.sendFile(path.join(PUBLIC_DIR, "index.html")));

// ==== Запуск сервера ====
app.listen(PORT, () => console.log(`✅ Server started on ${PORT}`));
