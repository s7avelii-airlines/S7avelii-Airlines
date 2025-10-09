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

// ==== База данных ====
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ==== Middleware ====
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// 🔥 Разрешаем запросы с твоего статичного сайта:
app.use(cors({
  origin: ["https://www.s7avelii-airlines.ru"], // ← твой домен
  credentials: true
}));

app.use(
  session({
    secret: process.env.SESSION_SECRET || "supersecret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: true,               // обязательно для HTTPS
      sameSite: "none",           // чтобы кросс-доменно работали куки
      maxAge: 1000 * 60 * 60 * 24 * 7
    }
  })
);

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
      avatar TEXT,
      bonus_miles INTEGER DEFAULT 0,
      status_miles INTEGER DEFAULT 0,
      cart JSONB DEFAULT '[]',
      dob TEXT,
      gender TEXT,
      vk TEXT,
      telegram TEXT,
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
  const { rows } = await pool.query("SELECT COUNT(*) FROM products");
  if (Number(rows[0].count) === 0) {
    await pool.query(`
      INSERT INTO products (name, price)
      VALUES ('Брелок S7avelii', 500),
             ('Футболка S7avelii', 1200),
             ('Кружка S7avelii', 800),
             ('Модель самолёта', 2500);
    `);
  }
}
initDB();

// ==== API ====
app.post("/api/register", async (req, res) => {
  try {
    const { fio, phone, email, password, dob, gender, card_number, card_type } = req.body;
    if (!phone || !password) return res.status(400).json({ error: "Введите телефон и пароль" });

    const hash = await bcrypt.hash(password, 10);
    const { rows } = await pool.query(
      `INSERT INTO users (fio, phone, email, password, dob, gender, card_number, card_type)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
       RETURNING id, fio, phone, email, card_number, card_type`,
      [fio, phone, email, hash, dob, gender, card_number, card_type]
    );
    req.session.userId = rows[0].id;
    res.json(rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Ошибка регистрации" });
  }
});

app.post("/api/login", async (req, res) => {
  const { phone, password } = req.body;
  const { rows } = await pool.query("SELECT * FROM users WHERE phone=$1", [phone]);
  const user = rows[0];
  if (!user) return res.status(400).json({ error: "Пользователь не найден" });
  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(400).json({ error: "Неверный пароль" });
  req.session.userId = user.id;
  res.json({ id: user.id, fio: user.fio, phone: user.phone });
});

app.get("/api/profile", async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: "Не авторизован" });
  const { rows } = await pool.query("SELECT * FROM users WHERE id=$1", [req.session.userId]);
  res.json(rows[0]);
});

// ==== Fallback ====
app.get("*", (req, res) => res.sendFile(path.join(PUBLIC_DIR, "index.html")));

// ==== Запуск ====
app.listen(PORT, () => console.log(`✅ Server started on ${PORT}`));
