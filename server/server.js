// server.js
import express from "express";
import path from "path";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import session from "express-session";
import cookieParser from "cookie-parser";
import cors from "cors";
import pkg from "pg";

dotenv.config();
const { Pool } = pkg;

const app = express();
const PORT = process.env.PORT || 10000;
const __dirname = path.resolve();

// ========== Config (env) ==========
// REQUIRED in .env: DATABASE_URL, SESSION_SECRET
// Optional: ALLOWED_ORIGINS (comma-separated list), NODE_ENV

const DATABASE_URL = process.env.DATABASE_URL;
const SESSION_SECRET = process.env.SESSION_SECRET || "please-change-this";
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "").split(",").map(s => s.trim()).filter(Boolean);
// Example ALLOWED_ORIGINS: "https://www.s7avelii-airlines.ru,https://s7avelii-airlines-frontend.onrender.com"

// ========== DB ==========
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: DATABASE_URL ? { rejectUnauthorized: false } : false
});

// quick DB connection check
(async function checkDb() {
  try {
    const r = await pool.query("SELECT NOW()");
    console.log("✅ Postgres connected:", r.rows[0]);
  } catch (err) {
    console.error("❌ Postgres connection error:", err.message || err);
    // don't exit — render will show logs; you may want to exit in CI: process.exit(1)
  }
})();

// ========== Middleware ==========
/*
 CORS MUST be applied before routes. For cross-site cookies:
  - credentials: true on both server and fetch
  - cookie.sameSite = 'none' and cookie.secure = true (HTTPS)
  - set app.set('trust proxy', 1) when behind proxy (Render)
*/
if (process.env.NODE_ENV === "production") {
  app.set("trust proxy", 1); // trusting first proxy (Render)
}

const corsOptions = {
  origin: ALLOWED_ORIGINS.length ? ALLOWED_ORIGINS : false, // false -> block if not set
  credentials: true,
  optionsSuccessStatus: 200
};
app.use(cors(corsOptions));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Session config — MemoryStore is fine for small projects; consider a DB-backed store in prod.
app.use(session({
  name: "s7avelii.sid",
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === "production", // true on HTTPS
    sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
    httpOnly: true,
    maxAge: 1000 * 60 * 60 * 24 * 7
  }
}));

// ========== Static files ==========
const PUBLIC_DIR = path.join(__dirname, "public");
app.use(express.static(PUBLIC_DIR));

// ========== DB init (tables) ==========
async function initDB() {
  try {
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
        INSERT INTO products (name, price) VALUES
        ('Брелок S7avelii', 500),
        ('Футболка S7avelii', 1200),
        ('Кружка S7avelii', 800),
        ('Модель самолёта', 2500);
      `);
    }
    console.log("✅ DB initialized");
  } catch (err) {
    console.error("❌ initDB error:", err);
  }
}
initDB();

// ========== Helpers ==========
function requireAuth(req, res, next) {
  if (!req.session?.userId) return res.status(401).json({ error: "Не авторизован" });
  next();
}

// ========== Test route ==========
app.get("/api/testdb", async (req, res) => {
  try {
    const { rows } = await pool.query("SELECT 1 AS ok");
    res.json({ ok: rows[0].ok === 1 });
  } catch (err) {
    console.error("testdb error:", err);
    res.status(500).json({ error: err.message || "DB error" });
  }
});

// ========== Auth / User API ==========
app.post("/api/register", async (req, res) => {
  try {
    const { fio, phone, email, password, cardNumber, cardType, dob, gender } = req.body;
    if (!phone || !password) return res.status(400).json({ error: "Введите телефон и пароль" });

    const hash = await bcrypt.hash(password, 10);
    const { rows } = await pool.query(
      `INSERT INTO users (fio, phone, email, password, card_number, card_type, dob, gender)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
       RETURNING id, fio, phone, email, card_number, card_type`,
      [fio || null, phone, email || null, hash, cardNumber || null, cardType || null, dob || null, gender || null]
    );
    req.session.userId = rows[0].id;
    res.json(rows[0]);
  } catch (err) {
    console.error("register error:", err);
    // unique phone violation
    if (err.code === "23505") return res.status(400).json({ error: "Телефон уже зарегистрирован" });
    res.status(500).json({ error: "Ошибка регистрации" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { phone, password } = req.body;
    if (!phone || !password) return res.status(400).json({ error: "Введите phone и password" });

    const { rows } = await pool.query("SELECT * FROM users WHERE phone=$1", [phone]);
    const user = rows[0];
    if (!user) return res.status(400).json({ error: "Пользователь не найден" });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(400).json({ error: "Неверный пароль" });

    req.session.userId = user.id;
    res.json({ id: user.id, fio: user.fio, phone: user.phone, email: user.email, card_number: user.card_number, card_type: user.card_type });
  } catch (err) {
    console.error("login error:", err);
    res.status(500).json({ error: "Ошибка входа" });
  }
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("s7avelii.sid", { path: "/" });
    res.json({ ok: true });
  });
});

app.get("/api/profile", async (req, res) => {
  try {
    if (!req.session?.userId) return res.status(401).json({ error: "Не авторизован" });
    const { rows } = await pool.query("SELECT id,fio,phone,email,card_number,card_type,bonus_miles,status_miles,avatar,dob,gender FROM users WHERE id=$1", [req.session.userId]);
    res.json(rows[0]);
  } catch (err) {
    console.error("profile error:", err);
    res.status(500).json({ error: "Ошибка" });
  }
});

app.post("/api/profile/update", requireAuth, async (req, res) => {
  try {
    const updates = [];
    const values = [];
    let i = 1;
    for (const key in req.body) {
      // map frontend keys -> DB columns if necessary
      const dbKey = key === "cardNumber" ? "card_number" : (key === "cardType" ? "card_type" : key);
      updates.push(`${dbKey}=$${i++}`);
      values.push(req.body[key]);
    }
    if (!updates.length) return res.json({ ok: true });
    values.push(req.session.userId);
    await pool.query(`UPDATE users SET ${updates.join(", ")} WHERE id=$${i}`, values);
    res.json({ ok: true });
  } catch (err) {
    console.error("profile update error:", err);
    res.status(500).json({ error: "Ошибка обновления профиля" });
  }
});

// ========== Products ==========
app.get("/api/products", async (req, res) => {
  try {
    const { rows } = await pool.query("SELECT * FROM products ORDER BY id");
    res.json(rows);
  } catch (err) {
    console.error("products error:", err);
    res.status(500).json({ error: "Ошибка" });
  }
});

// ========== Cart ==========
app.get("/api/cart", requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query("SELECT cart FROM users WHERE id=$1", [req.session.userId]);
    res.json(rows[0].cart || []);
  } catch (err) {
    console.error("cart get error:", err);
    res.status(500).json({ error: "Ошибка" });
  }
});

app.post("/api/cart/add", requireAuth, async (req, res) => {
  try {
    const { id, qty = 1 } = req.body;
    const { rows: pr } = await pool.query("SELECT id, name, price FROM products WHERE id=$1", [id]);
    if (!pr.length) return res.status(404).json({ error: "Нет такого товара" });
    const item = { id: pr[0].id, name: pr[0].name, price: pr[0].price, qty };
    await pool.query("UPDATE users SET cart = COALESCE(cart,'[]')::jsonb || $1::jsonb WHERE id=$2", [JSON.stringify([item]), req.session.userId]);
    res.json({ ok: true });
  } catch (err) {
    console.error("cart add error:", err);
    res.status(500).json({ error: "Ошибка" });
  }
});

app.post("/api/cart/clear", requireAuth, async (req, res) => {
  try {
    await pool.query("UPDATE users SET cart='[]' WHERE id=$1", [req.session.userId]);
    res.json({ ok: true });
  } catch (err) {
    console.error("cart clear error:", err);
    res.status(500).json({ error: "Ошибка" });
  }
});

// ========== Orders ==========
app.post("/api/orders/create", requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query("SELECT cart FROM users WHERE id=$1", [req.session.userId]);
    const cart = rows[0].cart || [];
    if (!cart.length) return res.status(400).json({ error: "Корзина пуста" });
    await pool.query("INSERT INTO orders (user_id, items) VALUES ($1,$2)", [req.session.userId, JSON.stringify(cart)]);
    await pool.query("UPDATE users SET cart='[]', bonus_miles = bonus_miles + 100 WHERE id=$1", [req.session.userId]);
    res.json({ ok: true });
  } catch (err) {
    console.error("create order error:", err);
    res.status(500).json({ error: "Ошибка" });
  }
});

app.get("/api/orders", requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query("SELECT * FROM orders WHERE user_id=$1 ORDER BY id DESC", [req.session.userId]);
    res.json(rows.map(o => ({ ...o, items: o.items || [] })));
  } catch (err) {
    console.error("orders get error:", err);
    res.status(500).json({ error: "Ошибка" });
  }
});

// ========== SPA fallback ==========
app.get("*", (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, "index.html"));
});

// ========== Start ==========
app.listen(PORT, () => {
  console.log(`✅ Server started on ${PORT}`);
  if (ALLOWED_ORIGINS.length) console.log("Allowed origins:", ALLOWED_ORIGINS);
});
