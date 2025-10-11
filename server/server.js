// server.js
import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import cookieParser from "cookie-parser";
import session from "express-session";
import connectPgSimple from "connect-pg-simple";
import bcrypt from "bcryptjs";
import pg from "pg";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 10000;
const FRONTEND_ORIGIN = process.env.CORS_ORIGIN || "https://www.s7avelii-airlines.ru";

// Postgres pool (Neon)
const { Pool } = pg;
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Middleware
app.use(express.json({ limit: "5mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(cors({
  origin: FRONTEND_ORIGIN,
  credentials: true
}));

// Session store in Postgres
const PgSession = connectPgSimple(session);
app.use(session({
  store: new PgSession({
    pool,                // connection pool
    tableName: "session" // recommended default
  }),
  secret: process.env.SESSION_SECRET || "s7avelii-secret",
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    secure: process.env.NODE_ENV === "production", // must be true on HTTPS
    sameSite: "none"
  }
}));

/* ---------- DB init (create tables if not exist) ---------- */
async function initDB() {
  // sessions table for connect-pg-simple (if not exists)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS session (
      sid varchar NOT NULL COLLATE "default",
      sess json NOT NULL,
      expire timestamp(6) NOT NULL,
      PRIMARY KEY (sid)
    );
  `);

  // users
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      fio TEXT,
      phone TEXT UNIQUE,
      email TEXT UNIQUE,
      password TEXT,
      dob TEXT,
      gender TEXT,
      card_number TEXT,
      card_type TEXT,
      avatar TEXT,
      bonus_miles INTEGER DEFAULT 0,
      status_miles INTEGER DEFAULT 0,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);

  // products
  await pool.query(`
    CREATE TABLE IF NOT EXISTS products (
      id SERIAL PRIMARY KEY,
      name TEXT,
      price INTEGER
    );
  `);

  // cart (one row per user+product)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS cart (
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      product_id INTEGER REFERENCES products(id),
      name TEXT,
      price INTEGER,
      qty INTEGER DEFAULT 1,
      PRIMARY KEY (user_id, product_id)
    );
  `);

  // orders
  await pool.query(`
    CREATE TABLE IF NOT EXISTS orders (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      items JSONB,
      total INTEGER,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);

  // seed some products if none
  const { rows } = await pool.query("SELECT COUNT(*) FROM products");
  if (Number(rows[0].count) === 0) {
    await pool.query(`
      INSERT INTO products (name, price)
      VALUES
        ('Брелок S7avelii', 500),
        ('Футболка S7avelii', 1200),
        ('Кружка S7avelii', 800),
        ('Модель самолёта', 2500);
    `);
    console.log("Seeded products");
  }
}

initDB().catch(err => {
  console.error("DB init failed:", err);
  process.exit(1);
});

/* ---------- Helpers ---------- */
function safeUser(u) {
  if (!u) return null;
  const { password, ...rest } = u;
  return rest;
}

/* ---------- Routes ---------- */

// simple DB test
app.get("/api/test-db", async (req, res) => {
  try {
    const r = await pool.query("SELECT NOW() as now");
    res.json({ ok: true, time: r.rows[0].now });
  } catch (err) {
    console.error("test-db err:", err);
    res.status(500).json({ ok: false, error: "DB error" });
  }
});

// register
app.post("/api/register", async (req, res) => {
  try {
    const { fio, phone, email, password, dob, gender, cardNumber, cardType } = req.body;
    if (!fio || !phone || !email || !password) {
      return res.status(400).json({ error: "Поля fio, phone, email и password обязательны" });
    }

    const hashed = await bcrypt.hash(password, 10);
    // check existing
    const ex = await pool.query("SELECT id FROM users WHERE phone=$1 OR email=$2", [phone, email]);
    if (ex.rows.length) return res.status(400).json({ error: "Пользователь с таким email/phone уже зарегистрирован" });

    const ins = await pool.query(
      `INSERT INTO users (fio, phone, email, password, dob, gender, card_number, card_type)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
      [fio, phone, email, hashed, dob || null, gender || null, cardNumber || null, cardType || null]
    );

    // create session
    req.session.userId = ins.rows[0].id;

    res.json({ ok: true, user: safeUser(ins.rows[0]) });
  } catch (err) {
    console.error("register err:", err);
    res.status(500).json({ error: "Ошибка регистрации" });
  }
});

// login (by phone or email)
app.post("/api/login", async (req, res) => {
  try {
    const { phone, email, password } = req.body;
    if ((!phone && !email) || !password) return res.status(400).json({ error: "Нужен phone или email и пароль" });

    const q = phone ? "SELECT * FROM users WHERE phone=$1" : "SELECT * FROM users WHERE email=$1";
    const param = phone || email;
    const r = await pool.query(q, [param]);
    const user = r.rows[0];
    if (!user) return res.status(400).json({ error: "Пользователь не найден" });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(400).json({ error: "Неверный пароль" });

    req.session.userId = user.id;
    res.json({ ok: true, user: safeUser(user) });
  } catch (err) {
    console.error("login err:", err);
    res.status(500).json({ error: "Ошибка входа" });
  }
});

// logout
app.post("/api/logout", (req, res) => {
  req.session.destroy(err => {
    if (err) console.warn("session destroy:", err);
    res.clearCookie("connect.sid", { path: "/" });
    res.json({ ok: true });
  });
});

// get profile
app.get("/api/profile", async (req, res) => {
  try {
    if (!req.session.userId) return res.status(401).json({ error: "Не авторизован" });
    const r = await pool.query("SELECT * FROM users WHERE id=$1", [req.session.userId]);
    res.json(safeUser(r.rows[0]));
  } catch (err) {
    console.error("profile err:", err);
    res.status(500).json({ error: "Ошибка профиля" });
  }
});

// update profile
app.post("/api/profile/update", async (req, res) => {
  try {
    if (!req.session.userId) return res.status(401).json({ error: "Не авторизован" });
    const allowed = ["fio","phone","email","dob","gender","card_number","card_type","avatar","bonus_miles"];
    const keys = Object.keys(req.body).filter(k => allowed.includes(k));
    if (!keys.length) return res.json({ ok: true });

    const vals = keys.map(k => req.body[k]);
    const sets = keys.map((k, i) => `${k}=$${i+1}`).join(",");
    vals.push(req.session.userId);
    await pool.query(`UPDATE users SET ${sets} WHERE id=$${vals.length}`, vals);
    const r = await pool.query("SELECT * FROM users WHERE id=$1", [req.session.userId]);
    res.json({ ok: true, user: safeUser(r.rows[0]) });
  } catch (err) {
    console.error("profile update err:", err);
    res.status(500).json({ error: "Ошибка обновления" });
  }
});

/* ---------- Products ---------- */
app.get("/api/products", async (req, res) => {
  try {
    const r = await pool.query("SELECT * FROM products ORDER BY id");
    res.json(r.rows);
  } catch (err) {
    console.error("products err:", err);
    res.status(500).json({ error: "Ошибка получения товаров" });
  }
});

/* ---------- Cart ---------- */
// get cart for user
app.get("/api/cart", async (req, res) => {
  try {
    if (!req.session.userId) return res.json([]);
    const r = await pool.query("SELECT product_id as id, name, price, qty FROM cart WHERE user_id=$1", [req.session.userId]);
    res.json(r.rows);
  } catch (err) {
    console.error("cart get err:", err);
    res.status(500).json({ error: "Ошибка корзины" });
  }
});

// add to cart { productId, qty }
app.post("/api/cart/add", async (req, res) => {
  try {
    if (!req.session.userId) return res.status(401).json({ error: "Не авторизован" });
    const { id: productId, qty = 1 } = req.body;
    const p = await pool.query("SELECT * FROM products WHERE id=$1", [productId]);
    if (!p.rows.length) return res.status(404).json({ error: "Нет такого товара" });
    const prod = p.rows[0];

    // upsert: insert or increment qty
    await pool.query(`
      INSERT INTO cart (user_id, product_id, name, price, qty)
      VALUES ($1,$2,$3,$4,$5)
      ON CONFLICT (user_id, product_id)
      DO UPDATE SET qty = cart.qty + EXCLUDED.qty
    `, [req.session.userId, prod.id, prod.name, prod.price, qty]);

    res.json({ ok: true });
  } catch (err) {
    console.error("cart add err:", err);
    res.status(500).json({ error: "Ошибка добавления в корзину" });
  }
});

// remove from cart { productId }
app.post("/api/cart/remove", async (req, res) => {
  try {
    if (!req.session.userId) return res.status(401).json({ error: "Не авторизован" });
    const { id: productId } = req.body;
    await pool.query("DELETE FROM cart WHERE user_id=$1 AND product_id=$2", [req.session.userId, productId]);
    res.json({ ok: true });
  } catch (err) {
    console.error("cart remove err:", err);
    res.status(500).json({ error: "Ошибка удаления из корзины" });
  }
});

// checkout
app.post("/api/cart/checkout", async (req, res) => {
  try {
    if (!req.session.userId) return res.status(401).json({ error: "Не авторизован" });
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const cartRes = await client.query("SELECT product_id, name, price, qty FROM cart WHERE user_id=$1", [req.session.userId]);
      const items = cartRes.rows;
      if (!items.length) { await client.query("ROLLBACK"); return res.status(400).json({ error: "Корзина пуста" }); }
      const total = items.reduce((s, it) => s + (it.price * it.qty), 0);

      await client.query("INSERT INTO orders (user_id, items, total) VALUES ($1,$2,$3)", [req.session.userId, JSON.stringify(items), total]);
      await client.query("DELETE FROM cart WHERE user_id=$1", [req.session.userId]);

      // add bonus miles (example: 1 mile per 10 currency)
      const milesToAdd = Math.floor(total / 10);
      await client.query("UPDATE users SET bonus_miles = bonus_miles + $1 WHERE id=$2", [milesToAdd, req.session.userId]);

      await client.query("COMMIT");
      res.json({ ok: true, total, milesAdded: milesToAdd });
    } catch (txErr) {
      await client.query("ROLLBACK");
      throw txErr;
    } finally {
      client.release();
    }
  } catch (err) {
    console.error("checkout err:", err);
    res.status(500).json({ error: "Ошибка оформления" });
  }
});

/* ---------- Orders ---------- */
app.get("/api/orders", async (req, res) => {
  try {
    if (!req.session.userId) return res.json([]);
    const r = await pool.query("SELECT id, items, total, created_at FROM orders WHERE user_id=$1 ORDER BY id DESC", [req.session.userId]);
    res.json(r.rows.map(o => ({ ...o, items: o.items || [] })));
  } catch (err) {
    console.error("orders err:", err);
    res.status(500).json({ error: "Ошибка заказов" });
  }
});

/* ---------- SPA fallback (optional) ---------- */
app.get("/", (req, res) => res.json({ ok: true }));

/* ---------- Start ---------- */
app.listen(PORT, () => {
  console.log(`✅ Server started on ${PORT}`);
});
