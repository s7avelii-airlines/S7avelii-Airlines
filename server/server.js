import express from "express";
import session from "express-session";
import cookieParser from "cookie-parser";
import bcrypt from "bcryptjs";
import pg from "pg";
import connectPgSimple from "connect-pg-simple";
import path from "path";
import dotenv from "dotenv";
import cors from "cors";
import { fileURLToPath } from "url";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// PostgreSQL pool
const { Pool } = pg;
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// Test connection
pool.connect()
  .then(() => console.log("✅ Connected to PostgreSQL"))
  .catch(err => console.error("❌ Database connection error:", err));

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(cors({
  origin: [
    "https://твоя-ссылка-на-github-io", // замени на свой домен
  ],
  credentials: true
}));

// Session store
const PgSession = connectPgSimple(session);
app.use(session({
  store: new PgSession({ pool, tableName: "session" }),
  name: "s7avelii.sid",
  secret: process.env.SESSION_SECRET || "super_secret_key",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: true,
    sameSite: "none",
    maxAge: 7 * 24 * 60 * 60 * 1000
  },
}));

// Utils
function makeId() {
  return Date.now().toString(36) + Math.random().toString(36).substring(2, 8);
}
function cleanUser(user) {
  const u = { ...user };
  delete u.password;
  return u;
}

// Register
app.post("/api/register", async (req, res) => {
  try {
    const { fio, phone, email, password } = req.body;
    if (!fio || !phone || !password)
      return res.status(400).json({ error: "ФИО, телефон и пароль обязательны" });

    const exist = await pool.query("SELECT * FROM users WHERE phone=$1", [phone]);
    if (exist.rows.length > 0)
      return res.status(400).json({ error: "Такой пользователь уже существует" });

    const hashed = await bcrypt.hash(password, 10);
    const id = makeId();

    const result = await pool.query(`
      INSERT INTO users (id, fio, phone, email, password, created_at)
      VALUES ($1,$2,$3,$4,$5,NOW()) RETURNING *;
    `, [id, fio, phone, email || "", hashed]);

    req.session.userId = id;
    res.json({ ok: true, user: cleanUser(result.rows[0]) });
  } catch (err) {
    console.error("Register error:", err);
    res.status(500).json({ error: "Ошибка сервера" });
  }
});

// Login
app.post("/api/login", async (req, res) => {
  try {
    const { phone, password } = req.body;
    if (!phone || !password)
      return res.status(400).json({ error: "Введите телефон и пароль" });

    const result = await pool.query("SELECT * FROM users WHERE phone=$1", [phone]);
    if (result.rows.length === 0)
      return res.status(400).json({ error: "Пользователь не найден" });

    const user = result.rows[0];
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(400).json({ error: "Неверный пароль" });

    req.session.userId = user.id;
    res.json({ ok: true, user: cleanUser(user) });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Ошибка сервера" });
  }
});

// Profile
app.get("/api/profile", async (req, res) => {
  try {
    if (!req.session.userId)
      return res.status(401).json({ error: "Не авторизован" });

    const result = await pool.query("SELECT * FROM users WHERE id=$1", [req.session.userId]);
    if (result.rows.length === 0)
      return res.status(404).json({ error: "Пользователь не найден" });

    res.json({ ok: true, user: cleanUser(result.rows[0]) });
  } catch (err) {
    console.error("Profile error:", err);
    res.status(500).json({ error: "Ошибка сервера" });
  }
});

app.get("/", (_, res) => res.send("✅ Сервер S7avelii работает! 🚀"));

app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));

