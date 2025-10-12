// server.js
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import pkg from "pg";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import multer from "multer";
import path from "path";
import { fileURLToPath } from "url";
import fs from "fs";

dotenv.config();
const { Pool } = pkg;
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || "change_this_secret";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// --- База ---
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

pool.connect()
  .then(c => { console.log("✅ DB connected"); c.release(); })
  .catch(err => console.error("❌ DB connection error:", err));

// --- Инициализация БД ---
async function initDB() {
  try {
    await pool.query(`CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      fio TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      phone TEXT UNIQUE,
      password TEXT NOT NULL,
      dob DATE,
      gender TEXT,
      card_number TEXT,
      card_type TEXT,
      avatar TEXT,
      bonus_miles INTEGER DEFAULT 0,
      status_miles INTEGER DEFAULT 0
    )`);
    console.log("✅ DB initialized");
  } catch (err) {
    console.error("DB init failed:", err);
    throw err;
  }
}
initDB().catch(() => {});

// --- JWT helper ---
function signToken(userId) {
  return jwt.sign({ id: userId }, JWT_SECRET, { expiresIn: "7d" });
}

// --- Auth middleware ---
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

// --- Express ---
const app = express();
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// --- Multer для аватарки ---
const upload = multer({ dest: path.join(__dirname, "uploads/") });

// --- Роуты ---

// Регистрация
app.post("/api/register", async (req, res) => {
  try {
    const { fio, email, phone, password, dob, gender, cardNumber, cardType } = req.body;
    if (!fio || !email || !password) return res.status(400).json({ error: "fio,email,password required" });

    const exists = await pool.query("SELECT id FROM users WHERE email=$1 OR phone=$2", [email, phone]);
    if (exists.rows.length) return res.status(400).json({ error: "User exists" });

    const hash = await bcrypt.hash(password, 10);
    const r = await pool.query(
      `INSERT INTO users (fio,email,phone,password,dob,gender,card_number,card_type) 
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`,
      [fio, email, phone, hash, dob || null, gender || null, cardNumber || null, cardType || null]
    );
    const token = signToken(r.rows[0].id);
    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Registration failed" });
  }
});

// Вход
app.post("/api/login", async (req, res) => {
  try {
    const { identifier, password } = req.body;
    if (!identifier || !password) return res.status(400).json({ error: "identifier,password required" });

    const r = await pool.query(
      "SELECT * FROM users WHERE email=$1 OR phone=$1",
      [identifier]
    );
    const user = r.rows[0];
    if (!user) return res.status(400).json({ error: "User not found" });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(400).json({ error: "Wrong password" });

    const token = signToken(user.id);
    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Login failed" });
  }
});

// Получить профиль
app.get("/api/profile", authMiddleware, async (req, res) => {
  try {
    const r = await pool.query("SELECT * FROM users WHERE id=$1", [req.userId]);
    const user = r.rows[0];
    if (!user) return res.status(404).json({ error: "Not found" });
    delete user.password;
    res.json(user);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Profile error" });
  }
});

// Обновление профиля
app.put("/api/profile", authMiddleware, async (req, res) => {
  try {
    const { fio, dob, gender, email, phone, cardNumber, cardType } = req.body;
    await pool.query(
      `UPDATE users SET fio=$1,dob=$2,gender=$3,email=$4,phone=$5,card_number=$6,card_type=$7 WHERE id=$8`,
      [fio, dob, gender, email, phone, cardNumber, cardType, req.userId]
    );
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Update failed" });
  }
});

// Загрузка аватарки
app.post("/api/profile/avatar", authMiddleware, upload.single("avatar"), async (req, res) => {
  try {
    const filePath = "/uploads/" + req.file.filename;
    await pool.query("UPDATE users SET avatar=$1 WHERE id=$2", [filePath, req.userId]);
    res.json({ avatar: filePath });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Avatar upload failed" });
  }
});

// --- Запуск сервера ---
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
