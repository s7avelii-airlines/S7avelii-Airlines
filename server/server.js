import express from "express";
import path from "path";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import session from "express-session";
import cookieParser from "cookie-parser";
import pkg from "pg";

dotenv.config();
const { Pool } = pkg;

const app = express();
const PORT = process.env.PORT || 3000;
const __dirname = path.resolve();

// ==== Настройки базы ====
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ==== Middleware ====
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(
  session({
    secret: process.env.SESSION_SECRET || "supersecret",
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 1000 * 60 * 60 * 24 * 7 }
  })
);

// ==== Папка со статикой ====
const PUBLIC_DIR = path.join(__dirname, "../public");
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

// ==== Пользователь ====
app.post("/api/register", async (req, res) => {
  try {
    const { fio, phone, email, password } = req.body;
    if (!phone || !password)
      return res.status(400).json({ error: "Введите телефон и пароль" });
    const hash = await bcrypt.hash(password, 10);
    const { rows } = await pool.query(
      "INSERT INTO users (fio, phone, email, password) VALUES ($1,$2,$3,$4) RETURNING *",
      [fio, phone, email, hash]
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
  res.json(user);
});

app.get("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get("/api/profile", async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: "Не авторизован" });
  const { rows } = await pool.query("SELECT * FROM users WHERE id=$1", [req.session.userId]);
  res.json(rows[0]);
});

app.post("/api/profile/update", async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: "Не авторизован" });
  const updates = [];
  const values = [];
  let i = 1;
  for (const key in req.body) {
    updates.push(`${key}=$${i++}`);
    values.push(req.body[key]);
  }
  if (!updates.length) return res.json({ ok: true });
  values.push(req.session.userId);
  await pool.query(`UPDATE users SET ${updates.join(",")} WHERE id=$${i}`, values);
  res.json({ ok: true });
});

// ==== Продукты ====
app.get("/api/products", async (req, res) => {
  const { rows } = await pool.query("SELECT * FROM products ORDER BY id");
  res.json(rows);
});

// ==== Корзина ====
app.get("/api/cart", async (req, res) => {
  if (!req.session.userId) return res.json([]);
  const { rows } = await pool.query("SELECT cart FROM users WHERE id=$1", [req.session.userId]);
  res.json(rows[0].cart || []);
});

app.post("/api/cart/add", async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: "Не авторизован" });
  const { id } = req.body;
  const { rows: pr } = await pool.query("SELECT * FROM products WHERE id=$1", [id]);
  if (!pr.length) return res.status(404).json({ error: "Нет такого товара" });
  const item = { id: pr[0].id, name: pr[0].name, price: pr[0].price, qty: 1 };
  await pool.query(
    "UPDATE users SET cart = COALESCE(cart,'[]')::jsonb || $1::jsonb WHERE id=$2",
    [JSON.stringify([item]), req.session.userId]
  );
  res.json({ ok: true });
});

app.post("/api/cart/remove", async (req, res) => {
  const { id } = req.body;
  const { rows } = await pool.query("SELECT cart FROM users WHERE id=$1", [req.session.userId]);
  const newCart = (rows[0].cart || []).filter((x) => x.id !== id);
  await pool.query("UPDATE users SET cart=$1 WHERE id=$2", [JSON.stringify(newCart), req.session.userId]);
  res.json({ ok: true });
});

app.post("/api/cart/checkout", async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: "Не авторизован" });
  const { rows } = await pool.query("SELECT cart FROM users WHERE id=$1", [req.session.userId]);
  const cart = rows[0].cart || [];
  if (!cart.length) return res.json({ error: "Корзина пуста" });
  await pool.query("INSERT INTO orders (user_id, items) VALUES ($1,$2)", [req.session.userId, JSON.stringify(cart)]);
  await pool.query("UPDATE users SET cart='[]', bonus_miles = bonus_miles + 100 WHERE id=$1", [req.session.userId]);
  res.json({ ok: true });
});

// ==== Заказы ====
app.get("/api/orders", async (req, res) => {
  if (!req.session.userId) return res.json([]);
  const { rows } = await pool.query("SELECT * FROM orders WHERE user_id=$1 ORDER BY id DESC", [req.session.userId]);
  res.json(rows.map((o) => ({ ...o, items: o.items || [] })));
});

// ==== SPA fallback ====
app.get("*", (req, res) => res.sendFile(path.join(PUBLIC_DIR, "index.html")));

// ==== Запуск ====
app.listen(PORT, () => console.log(`✅ Server started on ${PORT}`));
