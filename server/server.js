import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import pkg from "pg";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

dotenv.config();
const { Pool } = pkg;

const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || "super_secret_change_me";
const STATIC_ORIGIN = process.env.STATIC_ORIGIN || "*";

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

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

// --- DB init ---
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
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS products (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      price INTEGER NOT NULL
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

  const r = await pool.query("SELECT COUNT(*) FROM products");
  if (Number(r.rows[0].count) === 0) {
    await pool.query(`
      INSERT INTO products (name, price) VALUES
      ('Брелок S7avelii', 500),
      ('Футболка S7avelii', 1200),
      ('Кружка S7avelii', 800),
      ('Модель самолёта', 2500)
    `);
  }

  console.log("✅ DB ready");
}
initDB();

// --- JWT helper ---
function signToken(userId) {
  return jwt.sign({ id: userId }, JWT_SECRET, { expiresIn: "14d" });
}

// --- Middleware ---
function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: "No token" });
  const token = header.split(" ")[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
}

// --- Routes ---

// Health check
app.get("/api/health", (_, res) => res.json({ ok: true }));

// Register
app.post("/api/register", async (req, res) => {
  try {
    const { fio, email, phone, password, dob, gender, cardNumber, cardType } = req.body;
    if (!fio || !email || !password)
      return res.status(400).json({ error: "fio, email, password required" });

    const exists = await pool.query(
      "SELECT id FROM users WHERE email=$1 OR phone=$2",
      [email, phone]
    );
    if (exists.rows.length) return res.status(400).json({ error: "User exists" });

    const hash = await bcrypt.hash(password, 10);
    const ins = await pool.query(
      `INSERT INTO users (fio, full_name, email, phone, password, dob, gender, card_number, card_type)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id`,
      [fio, fio, email, phone, hash, dob || null, gender || null, cardNumber || null, cardType || null]
    );

    const token = signToken(ins.rows[0].id);
    res.json({ token });
  } catch (e) {
    console.error("Register error:", e);
    res.status(500).json({ error: "Registration failed" });
  }
});

// Login
app.post("/api/login", async (req, res) => {
  try {
    const { identifier, password } = req.body;
    if (!identifier || !password) return res.status(400).json({ error: "Missing fields" });

    const userRes = await pool.query(
      "SELECT * FROM users WHERE email=$1 OR phone=$1",
      [identifier]
    );
    const user = userRes.rows[0];
    if (!user) return res.status(400).json({ error: "User not found" });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(400).json({ error: "Wrong password" });

    const token = signToken(user.id);
    res.json({ token });
  } catch (e) {
    console.error("Login error:", e);
    res.status(500).json({ error: "Login failed" });
  }
});

// Profile
app.get("/api/profile", authMiddleware, async (req, res) => {
  try {
    const user = await pool.query("SELECT * FROM users WHERE id=$1", [req.userId]);
    const u = user.rows[0];
    if (!u) return res.status(404).json({ error: "Not found" });
    delete u.password;
    res.json(u);
  } catch (e) {
    console.error("Profile error:", e);
    res.status(500).json({ error: "Profile failed" });
  }
});

// Update profile
app.put("/api/profile", authMiddleware, async (req, res) => {
  try {
    const { fio, email, phone, avatar, dob, gender, vk, telegram } = req.body;
    await pool.query(
      `UPDATE users SET fio=$1, email=$2, phone=$3, avatar=$4, dob=$5, gender=$6, vk=$7, telegram=$8 WHERE id=$9`,
      [fio, email, phone, avatar, dob, gender, vk, telegram, req.userId]
    );
    res.json({ ok: true });
  } catch (e) {
    console.error("Update profile:", e);
    res.status(500).json({ error: "Update failed" });
  }
});

// Products
app.get("/api/products", async (_, res) => {
  const r = await pool.query("SELECT * FROM products ORDER BY id");
  res.json(r.rows);
});

// --- Serve static frontend ---
app.use(express.static("public"));

app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
