// server/server.js
import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import pg from "pg";
import dotenv from "dotenv";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || "supersecret";

// Подключение к базе Neon
const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// Middleware
app.use(express.json({ limit: "5mb" }));
app.use(cookieParser());
app.use(cors({ origin: true, credentials: true }));

/* ===================== 🔐 AUTH ===================== */

// Регистрация
app.post("/api/register", async (req, res) => {
  const { fio, email, phone, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "Заполните все поля" });

  try {
    const hashed = await bcrypt.hash(password, 10);
    const user = await pool.query(
      `INSERT INTO users (fio, email, phone, password) VALUES ($1,$2,$3,$4) RETURNING id,fio,email,phone`,
      [fio, email, phone, hashed]
    );
    const token = jwt.sign({ id: user.rows[0].id }, JWT_SECRET, { expiresIn: "7d" });
    res.cookie("token", token, { httpOnly: true, sameSite: "lax" });
    res.json({ user: user.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Ошибка регистрации" });
  }
});

// Вход
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
    if (!result.rows.length) return res.status(401).json({ error: "Неверные данные" });
    const user = result.rows[0];
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ error: "Неверный пароль" });

    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: "7d" });
    res.cookie("token", token, { httpOnly: true, sameSite: "lax" });
    res.json({ user: { id: user.id, fio: user.fio, email: user.email, phone: user.phone } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Ошибка входа" });
  }
});

// Выход
app.get("/api/logout", (req, res) => {
  res.clearCookie("token");
  res.json({ message: "Вы вышли" });
});

// Middleware для проверки токена
async function auth(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: "Нет токена" });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ error: "Неверный токен" });
  }
}

/* ===================== 👤 PROFILE ===================== */

app.get("/api/profile", auth, async (req, res) => {
  const { id } = req.user;
  try {
    const result = await pool.query("SELECT * FROM users WHERE id=$1", [id]);
    res.json(result.rows[0]);
  } catch {
    res.status(500).json({ error: "Ошибка профиля" });
  }
});

app.post("/api/profile/update", auth, async (req, res) => {
  const { id } = req.user;
  const fields = req.body;
  const entries = Object.entries(fields);
  if (!entries.length) return res.json({ message: "Нечего обновлять" });

  try {
    const updates = [];
    const values = [];
    entries.forEach(([key, val], i) => {
      updates.push(`${key}=$${i + 1}`);
      values.push(val);
    });
    values.push(id);
    await pool.query(`UPDATE users SET ${updates.join(",")} WHERE id=$${values.length}`, values);
    res.json({ message: "Профиль обновлён" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Ошибка обновления профиля" });
  }
});

/* ===================== 🛍️ PRODUCTS ===================== */

app.get("/api/products", async (_, res) => {
  try {
    const r = await pool.query("SELECT * FROM products ORDER BY id");
    res.json(r.rows);
  } catch {
    res.status(500).json({ error: "Ошибка товаров" });
  }
});

/* ===================== 🧺 CART ===================== */

app.get("/api/cart", auth, async (req, res) => {
  const { id } = req.user;
  try {
    const r = await pool.query("SELECT * FROM cart WHERE user_id=$1", [id]);
    res.json(r.rows);
  } catch {
    res.status(500).json({ error: "Ошибка корзины" });
  }
});

app.post("/api/cart/add", auth, async (req, res) => {
  const { id } = req.user;
  const { id: productId } = req.body;
  try {
    const product = await pool.query("SELECT * FROM products WHERE id=$1", [productId]);
    if (!product.rows.length) return res.status(404).json({ error: "Товар не найден" });
    const p = product.rows[0];
    await pool.query(
      `INSERT INTO cart (user_id, product_id, name, price, qty) VALUES ($1,$2,$3,$4,1)
       ON CONFLICT (user_id, product_id) DO UPDATE SET qty = cart.qty + 1`,
      [id, p.id, p.name, p.price]
    );
    res.json({ message: "Добавлено" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Ошибка добавления в корзину" });
  }
});

app.post("/api/cart/remove", auth, async (req, res) => {
  const { id } = req.user;
  const { id: productId } = req.body;
  try {
    await pool.query("DELETE FROM cart WHERE user_id=$1 AND product_id=$2", [id, productId]);
    res.json({ message: "Удалено" });
  } catch {
    res.status(500).json({ error: "Ошибка удаления" });
  }
});

app.post("/api/cart/checkout", auth, async (req, res) => {
  const { id } = req.user;
  try {
    await pool.query("DELETE FROM cart WHERE user_id=$1", [id]);
    res.json({ message: "Заказ оформлен" });
  } catch {
    res.status(500).json({ error: "Ошибка оформления" });
  }
});

/* ===================== 🚀 START ===================== */

app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
