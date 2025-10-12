// === Импорты ===
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import pkg from "pg";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import path from "path";
import { fileURLToPath } from "url";

// === Конфигурация ===
dotenv.config();
const { Pool } = pkg;

const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || "super_secret_key";
const STATIC_ORIGIN = process.env.STATIC_ORIGIN || "*";

// === Подключение к базе ===
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// === Инициализация Express ===
const app = express();
app.use(express.json());
app.use(
  cors({
    origin: STATIC_ORIGIN,
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

// === Проверка БД ===
pool
  .connect()
  .then((c) => {
    console.log("✅ PostgreSQL connected");
    c.release();
  })
  .catch((err) => console.error("❌ DB connection error:", err));

// === Инициализация таблиц ===
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      fio TEXT NOT NULL,
      full_name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      phone TEXT UNIQUE,
      password TEXT NOT NULL,
      avatar TEXT,
      dob DATE,
      gender TEXT,
      vk TEXT,
      telegram TEXT,
      card_number TEXT,
      card_type TEXT,
      bonus_miles INTEGER DEFAULT 0,
      status_miles INTEGER DEFAULT 0,
      cart JSONB DEFAULT '[]'
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS products (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      price INTEGER NOT NULL
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS orders (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id),
      items JSONB,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);

  const { rows } = await pool.query("SELECT COUNT(*) FROM products");
  if (Number(rows[0].count) === 0) {
    await pool.query(`
      INSERT INTO products (name, price)
      VALUES 
      ('Брелок S7avelii', 500),
      ('Футболка S7avelii', 1200),
      ('Кружка S7avelii', 800),
      ('Модель самолёта', 2500)
    `);
  }

  console.log("✅ Database initialized");
}
initDB().catch(console.error);

// === JWT ===
function signToken(userId) {
  return jwt.sign({ id: userId }, JWT_SECRET, { expiresIn: "7d" });
}

function authMiddleware(req, res, next) {
  const h = req.headers.authorization;
  if (!h) return res.status(401).json({ error: "No token" });
  const token = h.split(" ")[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.id;
    next();
  } catch (e) {
    return res.status(401).json({ error: "Invalid token" });
  }
}

// === Утилиты ===
async function getUserById(id) {
  const { rows } = await pool.query("SELECT * FROM users WHERE id=$1", [id]);
  return rows[0] || null;
}

// === API ===

// Проверка здоровья
app.get("/api/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// Регистрация
app.post("/api/register", async (req, res) => {
  try {
    const { fio, email, phone, password, dob, gender, cardNumber, cardType } = req.body;
    if (!fio || !email || !password)
      return res.status(400).json({ error: "Введите ФИО, email и пароль" });

    const exist = await pool.query("SELECT id FROM users WHERE email=$1 OR phone=$2", [email, phone]);
    if (exist.rows.length)
      return res.status(400).json({ error: "Такой пользователь уже существует" });

    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      `INSERT INTO users (fio, full_name, email, phone, password, dob, gender, card_number, card_type)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id`,
      [fio, fio, email, phone, hash, dob || null, gender || null, cardNumber || null, cardType || null]
    );

    const token = signToken(result.rows[0].id);
    res.json({ token });
  } catch (err) {
    console.error("register err:", err);
    res.status(500).json({ error: "Ошибка регистрации" });
  }
});

// Вход
app.post("/api/login", async (req, res) => {
  try {
    const { phone, email, password } = req.body;
    if ((!phone && !email) || !password)
      return res.status(400).json({ error: "Введите телефон/email и пароль" });

    const r = await pool.query("SELECT * FROM users WHERE phone=$1 OR email=$1", [phone || email]);
    const user = r.rows[0];
    if (!user) return res.status(400).json({ error: "Пользователь не найден" });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(400).json({ error: "Неверный пароль" });

    const token = signToken(user.id);
    res.json({ token });
  } catch (err) {
    console.error("login err:", err);
    res.status(500).json({ error: "Ошибка входа" });
  }
});

// Профиль
app.get("/api/profile", authMiddleware, async (req, res) => {
  try {
    const user = await getUserById(req.userId);
    if (!user) return res.status(404).json({ error: "Пользователь не найден" });
    delete user.password;
    res.json(user);
  } catch (err) {
    console.error("profile err:", err);
    res.status(500).json({ error: "Ошибка получения профиля" });
  }
});

// Продукты
app.get("/api/products", async (req, res) => {
  try {
    const { rows } = await pool.query("SELECT * FROM products ORDER BY id");
    res.json(rows);
  } catch (err) {
    console.error("products err:", err);
    res.status(500).json({ error: "Ошибка получения товаров" });
  }
});

// === Статика (Frontend) ===
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
app.use(express.static(path.join(__dirname, "public")));

// Отдача index.html (или auth.html как главной)
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "auth.html"));
});

// === Запуск ===
app.listen(PORT, () => console.log(`✅ Server is live on port ${PORT}`));

