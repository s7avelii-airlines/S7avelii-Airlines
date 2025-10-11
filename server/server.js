import express from "express";
import cors from "cors";
import session from "express-session";
import pg from "pg";
import dotenv from "dotenv";
import bodyParser from "body-parser";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 10000;

// --- Middleware ---
app.use(cors({
  origin: process.env.CORS_ORIGIN,
  credentials: true,
}));
app.use(bodyParser.json());
app.use(session({
  secret: process.env.SESSION_SECRET || "supersecret",
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false }, // ставь true если https
}));

// --- Database ---
const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function initDB() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        fio TEXT,
        email TEXT UNIQUE,
        phone TEXT,
        password TEXT,
        avatar TEXT,
        dob DATE,
        gender TEXT,
        card_number TEXT,
        card_type TEXT,
        bonus_miles INT DEFAULT 0,
        status_miles INT DEFAULT 0,
        vk TEXT,
        telegram TEXT
      );
      CREATE TABLE IF NOT EXISTS products (
        id SERIAL PRIMARY KEY,
        name TEXT,
        price INT
      );
      CREATE TABLE IF NOT EXISTS cart_items (
        id SERIAL PRIMARY KEY,
        user_id INT REFERENCES users(id),
        product_id INT REFERENCES products(id),
        qty INT DEFAULT 1
      );
      CREATE TABLE IF NOT EXISTS orders (
        id SERIAL PRIMARY KEY,
        user_id INT REFERENCES users(id),
        product_id INT REFERENCES products(id),
        qty INT,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);
    console.log("DB initialized ✅");
  } catch (err) {
    console.error("DB init failed:", err);
  }
}

// --- Auth Routes ---
app.post("/api/register", async (req, res) => {
  const { fio, email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "Email и пароль обязательны" });
  try {
    const user = await pool.query(
      "INSERT INTO users (fio, email, password) VALUES ($1,$2,$3) RETURNING *",
      [fio, email, password]
    );
    req.session.userId = user.rows[0].id;
    res.json({ user: user.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Ошибка регистрации" });
  }
});

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await pool.query(
      "SELECT * FROM users WHERE email=$1 AND password=$2",
      [email, password]
    );
    if (!user.rows[0]) return res.status(401).json({ error: "Неверный email или пароль" });
    req.session.userId = user.rows[0].id;
    res.json({ user: user.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Ошибка входа" });
  }
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

// --- Profile Routes ---
app.get("/api/profile", async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: "Не авторизован" });
  try {
    const user = await pool.query("SELECT * FROM users WHERE id=$1", [req.session.userId]);
    res.json(user.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Ошибка профиля" });
  }
});

app.post("/api/profile/update", async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: "Не авторизован" });
  const fields = Object.keys(req.body);
  const values = Object.values(req.body);
  const setString = fields.map((f,i) => `${f}=$${i+1}`).join(",");
  try {
    await pool.query(`UPDATE users SET ${setString} WHERE id=$${fields.length+1}`, [...values, req.session.userId]);
    res.json({ ok: true });
  } catch(err) {
    console.error(err);
    res.status(500).json({ error: "Ошибка обновления профиля" });
  }
});

// --- Products ---
app.get("/api/products", async (req, res) => {
  try {
    const products = await pool.query("SELECT * FROM products");
    res.json(products.rows);
  } catch(err) {
    console.error(err);
    res.status(500).json({ error: "Ошибка продуктов" });
  }
});

// --- Cart ---
app.get("/api/cart", async (req, res) => {
  if (!req.session.userId) return res.json([]);
  try {
    const cart = await pool.query(`
      SELECT ci.id, p.name, p.price, ci.qty
      FROM cart_items ci
      JOIN products p ON p.id=ci.product_id
      WHERE ci.user_id=$1
    `, [req.session.userId]);
    res.json(cart.rows);
  } catch(err) {
    console.error(err);
    res.status(500).json({ error: "Ошибка корзины" });
  }
});

app.post("/api/cart/add", async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: "Не авторизован" });
  const { id } = req.body;
  try {
    const existing = await pool.query("SELECT * FROM cart_items WHERE user_id=$1 AND product_id=$2", [req.session.userId, id]);
    if (existing.rows[0]) {
      await pool.query("UPDATE cart_items SET qty=qty+1 WHERE id=$1", [existing.rows[0].id]);
    } else {
      await pool.query("INSERT INTO cart_items (user_id, product_id) VALUES ($1,$2)", [req.session.userId, id]);
    }
    res.json({ ok: true });
  } catch(err) {
    console.error(err);
    res.status(500).json({ error: "Ошибка добавления в корзину" });
  }
});

app.post("/api/cart/remove", async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: "Не авторизован" });
  const { id } = req.body;
  try {
    await pool.query("DELETE FROM cart_items WHERE id=$1 AND user_id=$2", [id, req.session.userId]);
    res.json({ ok: true });
  } catch(err) {
    console.error(err);
    res.status(500).json({ error: "Ошибка удаления из корзины" });
  }
});

app.post("/api/cart/checkout", async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: "Не авторизован" });
  try {
    const items = await pool.query("SELECT * FROM cart_items WHERE user_id=$1", [req.session.userId]);
    for (const item of items.rows) {
      await pool.query("INSERT INTO orders (user_id, product_id, qty) VALUES ($1,$2,$3)", [req.session.userId, item.product_id, item.qty]);
    }
    await pool.query("DELETE FROM cart_items WHERE user_id=$1", [req.session.userId]);
    res.json({ ok: true });
  } catch(err) {
    console.error(err);
    res.status(500).json({ error: "Ошибка оформления заказа" });
  }
});

// --- Orders ---
app.get("/api/orders", async (req, res) => {
  if (!req.session.userId) return res.json([]);
  try {
    const orders = await pool.query(`
      SELECT o.id, p.name, p.price, o.qty, o.created_at
      FROM orders o
      JOIN products p ON p.id=o.product_id
      WHERE o.user_id=$1
      ORDER BY o.created_at DESC
    `, [req.session.userId]);
    res.json(orders.rows);
  } catch(err) {
    console.error(err);
    res.status(500).json({ error: "Ошибка заказов" });
  }
});

// --- Start Server ---
app.listen(PORT, async () => {
  console.log(`✅ Server started on ${PORT}`);
  await initDB();
});
