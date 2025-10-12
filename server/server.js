// server.js
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import multer from "multer";
import path from "path";
import fs from "fs";
import pkg from "pg";
import { fileURLToPath } from "url";

dotenv.config();
const { Pool } = pkg;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || "change_this_secret";
const STATIC_ORIGIN = process.env.STATIC_ORIGIN || "*";
const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
  console.error("ERROR: DATABASE_URL must be set in environment variables");
  process.exit(1);
}

// Postgres pool (on Render set NODE_ENV=production to enable ssl)
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false,
});

pool.on("error", (err) => console.error("Postgres pool error:", err));

// create public/avatars
const PUBLIC_DIR = path.join(__dirname, "public");
const AVATARS_DIR = path.join(PUBLIC_DIR, "avatars");
fs.mkdirSync(AVATARS_DIR, { recursive: true });

// multer storage
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, AVATARS_DIR),
  filename: (req, file, cb) => {
    // filename will be set after token parsing middleware sets req.userId
    const ext = path.extname(file.originalname) || ".jpg";
    cb(null, `${Date.now()}-${Math.round(Math.random()*1e9)}${ext}`);
  },
});
const upload = multer({ storage });

// express setup
const app = express();
app.use(express.json({ limit: "5mb" }));
app.use(cors({
  origin: STATIC_ORIGIN,
  methods: ["GET","POST","PUT","DELETE","OPTIONS"],
  credentials: true,
  allowedHeaders: ["Content-Type","Authorization"],
}));
app.use("/avatars", express.static(AVATARS_DIR));
app.use(express.static(PUBLIC_DIR));

// helper: sign token
function signToken(userId) {
  return jwt.sign({ id: userId }, JWT_SECRET, { expiresIn: "30d" });
}

// middleware: auth from Authorization header
function authMiddleware(req, res, next) {
  const h = req.headers.authorization;
  if (!h) return res.status(401).json({ error: "No token" });
  const token = h.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token" });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.id;
    next();
  } catch (e) {
    return res.status(401).json({ error: "Invalid token" });
  }
}

// middleware for avatar route: parse token first
function parseTokenMiddleware(req, res, next) {
  const h = req.headers.authorization;
  if (!h) return res.status(401).json({ error: "No token" });
  const token = h.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token" });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.id;
    next();
  } catch (e) {
    return res.status(401).json({ error: "Invalid token" });
  }
}

// init DB (create tables)
async function initDB() {
  try {
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
        cart JSONB DEFAULT '[]',
        created_at TIMESTAMP DEFAULT NOW()
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
      console.log("Seeded products");
    }

    console.log("DB initialized");
  } catch (err) {
    console.error("DB init failed:", err);
    process.exit(1);
  }
}
initDB().catch(console.error);

// --- Routes ---

// health
app.get("/api/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// register
app.post("/api/register", async (req, res) => {
  try {
    const { fio, email, phone, password, dob, gender, cardNumber, cardType } = req.body;
    if (!fio || !email || !password) return res.status(400).json({ error: "fio,email,password required" });

    const chk = await pool.query("SELECT id FROM users WHERE email=$1 OR phone=$2", [email, phone]);
    if (chk.rows.length) return res.status(400).json({ error: "User exists" });

    const hash = await bcrypt.hash(password, 10);
    const q = `
      INSERT INTO users (fio, full_name, email, phone, password, dob, gender, card_number, card_type)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
      RETURNING id, fio, email, phone, avatar
    `;
    const r = await pool.query(q, [fio, fio, email, phone || null, hash, dob || null, gender || null, cardNumber || null, cardType || null]);
    const user = r.rows[0];
    const token = signToken(user.id);
    res.json({ token, user });
  } catch (err) {
    console.error("register err:", err);
    res.status(500).json({ error: "Registration failed" });
  }
});

// login
app.post("/api/login", async (req, res) => {
  try {
    const { identifier, password } = req.body; // identifier = email or phone
    if (!identifier || !password) return res.status(400).json({ error: "identifier and password required" });

    const r = await pool.query("SELECT * FROM users WHERE email=$1 OR phone=$1 LIMIT 1", [identifier]);
    const user = r.rows[0];
    if (!user) return res.status(400).json({ error: "User not found" });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(400).json({ error: "Wrong password" });

    const token = signToken(user.id);
    delete user.password;
    res.json({ token, user });
  } catch (err) {
    console.error("login err:", err);
    res.status(500).json({ error: "Login failed" });
  }
});

// profile GET
app.get("/api/profile", authMiddleware, async (req, res) => {
  try {
    const r = await pool.query("SELECT id,fio,full_name,email,phone,avatar,dob,gender,card_number,card_type,bonus_miles,status_miles,cart FROM users WHERE id=$1", [req.userId]);
    const user = r.rows[0];
    if (!user) return res.status(404).json({ error: "Not found" });
    res.json(user);
  } catch (err) {
    console.error("profile err:", err);
    res.status(500).json({ error: "Profile error" });
  }
});

// profile PUT
app.put("/api/profile", authMiddleware, async (req, res) => {
  try {
    const allowed = ['fio','email','phone','dob','gender','card_number','card_type','bonus_miles','status_miles'];
    const sets = [];
    const vals = [];
    let i = 1;
    for (const k of allowed) {
      if (req.body[k] !== undefined) {
        sets.push(`${k}=$${i++}`);
        vals.push(req.body[k]);
      }
    }
    if (!sets.length) return res.status(400).json({ error: "Nothing to update" });
    vals.push(req.userId);
    const q = `UPDATE users SET ${sets.join(', ')} WHERE id=$${i} RETURNING id,fio,full_name,email,phone,avatar,dob,gender,card_number,card_type,bonus_miles,status_miles,cart`;
    const r = await pool.query(q, vals);
    res.json(r.rows[0]);
  } catch (err) {
    console.error("profile.update err:", err);
    res.status(500).json({ error: "Update failed" });
  }
});

// avatar upload (parse token first)
app.post("/api/profile/avatar", parseTokenMiddleware, upload.single("avatar"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "No file" });
    // name avatar as userId + ext
    const ext = path.extname(req.file.originalname) || ".jpg";
    const filename = `${req.userId}${ext}`;
    const targetPath = path.join(AVATARS_DIR, filename);
    // replace file
    fs.renameSync(req.file.path, targetPath);
    const avatarPath = `/avatars/${filename}`;
    await pool.query("UPDATE users SET avatar=$1 WHERE id=$2", [avatarPath, req.userId]);
    res.json({ avatar: avatarPath });
  } catch (err) {
    console.error("avatar err:", err);
    res.status(500).json({ error: "Avatar upload failed" });
  }
});

// products
app.get("/api/products", async (req, res) => {
  try {
    const r = await pool.query("SELECT * FROM products ORDER BY id");
    res.json(r.rows);
  } catch (err) {
    console.error("products err:", err);
    res.status(500).json({ error: "Products error" });
  }
});

// cart endpoints
app.get("/api/cart", authMiddleware, async (req, res) => {
  try {
    const r = await pool.query("SELECT cart FROM users WHERE id=$1", [req.userId]);
    res.json(r.rows[0].cart || []);
  } catch (err) {
    console.error("cart.get err:", err);
    res.status(500).json({ error: "Cart error" });
  }
});

app.post("/api/cart/add", authMiddleware, async (req, res) => {
  try {
    const { id } = req.body;
    const p = (await pool.query("SELECT id,name,price FROM products WHERE id=$1", [id])).rows[0];
    if (!p) return res.status(404).json({ error: "Product not found" });
    const r = await pool.query("SELECT cart FROM users WHERE id=$1", [req.userId]);
    const cart = r.rows[0].cart || [];
    const found = cart.find(x => x.id === p.id);
    if (found) found.qty = (found.qty || 1) + 1;
    else cart.push({ id: p.id, name: p.name, price: p.price, qty: 1 });
    await pool.query("UPDATE users SET cart = $1 WHERE id=$2", [JSON.stringify(cart), req.userId]);
    res.json({ ok: true });
  } catch (err) {
    console.error("cart.add err:", err);
    res.status(500).json({ error: "Cart add error" });
  }
});

app.post("/api/cart/remove", authMiddleware, async (req, res) => {
  try {
    const { id } = req.body;
    const r = await pool.query("SELECT cart FROM users WHERE id=$1", [req.userId]);
    const cart = r.rows[0].cart || [];
    const newCart = cart.filter(x => x.id !== id);
    await pool.query("UPDATE users SET cart=$1 WHERE id=$2", [JSON.stringify(newCart), req.userId]);
    res.json({ ok: true });
  } catch (err) {
    console.error("cart.remove err:", err);
    res.status(500).json({ error: "Cart remove error" });
  }
});

app.post("/api/checkout", authMiddleware, async (req, res) => {
  try {
    const r = await pool.query("SELECT cart FROM users WHERE id=$1", [req.userId]);
    const cart = r.rows[0].cart || [];
    if (!cart.length) return res.status(400).json({ error: "Cart empty" });
    await pool.query("INSERT INTO orders (user_id, items) VALUES ($1,$2)", [req.userId, JSON.stringify(cart)]);
    await pool.query("UPDATE users SET cart = '[]', bonus_miles = COALESCE(bonus_miles,0) + 100 WHERE id=$1", [req.userId]);
    res.json({ ok: true });
  } catch (err) {
    console.error("checkout err:", err);
    res.status(500).json({ error: "Checkout error" });
  }
});

// orders
app.get("/api/orders", authMiddleware, async (req, res) => {
  try {
    const r = await pool.query("SELECT * FROM orders WHERE user_id=$1 ORDER BY id DESC", [req.userId]);
    res.json(r.rows);
  } catch (err) {
    console.error("orders err:", err);
    res.status(500).json({ error: "Orders error" });
  }
});

// fallback
app.get("/", (req, res) => res.send("✅ Server running"));

// start
app.listen(PORT, () => console.log(`✅ Server listening on ${PORT}`));
