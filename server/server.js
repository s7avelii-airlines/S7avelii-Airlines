import express from "express";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import pg from "pg";
import session from "express-session";
import cookieParser from "cookie-parser";
import cors from "cors";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 10000;

const { Pool } = pg;

// подключение к Neon
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// middleware
app.use(express.json());
app.use(cookieParser());
app.use(
  cors({
    origin: "https://www.s7avelii-airlines.ru", // твой статичный сайт
    credentials: true
  })
);
app.use(
  session({
    secret: process.env.SESSION_SECRET || "s7avelii-secret",
    resave: false,
    saveUninitialized: false,
    cookie: { secure: true, sameSite: "none" }
  })
);

// тест соединения с базой
app.get("/api/test-db", async (req, res) => {
  try {
    const result = await pool.query("SELECT NOW()");
    res.json({ ok: true, time: result.rows[0].now });
  } catch (err) {
    console.error("Ошибка подключения к БД:", err);
    res.status(500).json({ ok: false, error: "DB connection failed" });
  }
});

// регистрация
app.post("/api/register", async (req, res) => {
  try {
    const { fio, email, phone, password, cardNumber, cardType } = req.body;

    if (!fio || !email || !phone || !password)
      return res.status(400).json({ error: "Все поля обязательны" });

    const hash = await bcrypt.hash(password, 10);
    await pool.query(
      `CREATE TABLE IF NOT EXISTS users(
        id SERIAL PRIMARY KEY,
        fio TEXT,
        email TEXT UNIQUE,
        phone TEXT UNIQUE,
        password TEXT,
        card_number TEXT,
        card_type TEXT
      )`
    );

    const existing = await pool.query(
      "SELECT * FROM users WHERE email=$1 OR phone=$2",
      [email, phone]
    );
    if (existing.rows.length > 0)
      return res.status(400).json({ error: "Пользователь уже существует" });

    await pool.query(
      `INSERT INTO users (fio,email,phone,password,card_number,card_type)
       VALUES ($1,$2,$3,$4,$5,$6)`,
      [fio, email, phone, hash, cardNumber, cardType]
    );

    res.json({ ok: true, message: "Регистрация успешна" });
  } catch (err) {
    console.error("Ошибка регистрации:", err);
    res.status(500).json({ error: "Ошибка регистрации" });
  }
});

// вход
app.post("/api/login", async (req, res) => {
  try {
    const { phone, password } = req.body;
    if (!phone || !password)
      return res.status(400).json({ error: "Введите телефон и пароль" });

    const result = await pool.query("SELECT * FROM users WHERE phone=$1", [
      phone
    ]);
    const user = result.rows[0];
    if (!user) return res.status(400).json({ error: "Пользователь не найден" });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ error: "Неверный пароль" });

    req.session.user = { id: user.id, fio: user.fio };
    res.json({ ok: true, user: { fio: user.fio, email: user.email } });
  } catch (err) {
    console.error("Ошибка входа:", err);
    res.status(500).json({ error: "Ошибка входа" });
  }
});

// личный кабинет
app.get("/api/me", (req, res) => {
  if (!req.session.user)
    return res.status(401).json({ error: "Не авторизован" });
  res.json({ ok: true, user: req.session.user });
});

// запуск
app.listen(PORT, () =>
  console.log(`✅ Сервер запущен на порту ${PORT}`)
);
