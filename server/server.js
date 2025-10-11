import express from "express";
import session from "express-session";
import pg from "pg";
import dotenv from "dotenv";
import cors from "cors";
import bodyParser from "body-parser";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 10000;

// --- Middleware ---
app.use(cors({ origin: true, credentials: true }));
app.use(bodyParser.json());
app.use(session({
  secret: process.env.SESSION_SECRET || "secret",
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24*60*60*1000 } // 1 день
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
        password TEXT,
        phone TEXT,
        dob DATE,
        gender TEXT,
        avatar TEXT,
        card_number TEXT,
        card_type TEXT,
        bonus_miles INT DEFAULT 0,
        status_miles INT DEFAULT 0,
        vk TEXT,
        telegram TEXT
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS products (
        id SERIAL PRIMARY KEY,
        name TEXT,
        price INT
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS carts (
        id SERIAL PRIMARY KEY,
        user_id INT REFERENCES users(id),
        product_id INT REFERENCES products(id),
        qty INT DEFAULT 1
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS orders (
        id SERIAL PRIMARY KEY,
        user_id INT REFERENCES users(id),
        product_id INT REFERENCES products(id),
        qty INT,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    console.log("✅ DB initialized");
  } catch (err) {
    console.error("DB init failed:", err);
  }
}

// --- Helpers ---
function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: "Unauthorized" });
  next();
}

// --- Auth ---
app.post("/api/register", async (req, res) => {
  const { fio, email, password } = req.body;
  if (!fio || !email || !password) return res.status(400).json({ error: "Missing fields" });
  try {
    const result = await pool.query(
      "INSERT INTO users (fio, email, password) VALUES ($1,$2,$3) RETURNING id",
      [fio, email, password]
    );
    req.session.userId = result.rows[0].id;
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query("SELECT id FROM users WHERE email=$1 AND password=$2", [email, password]);
    if (!result.rows[0]) return res.status(401).json({ error: "Invalid credentials" });
    req.session.userId = result.rows[0].id;
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

// --- Profile ---
app.get("/api/profile", requireAuth, async (req, res) => {
  const user = await pool.query("SELECT * FROM users WHERE id=$1", [req.session.userId]);
  res.json({ user: user.rows[0] });
});

app.post("/api/profile/update", requireAuth, async (req, res) => {
  const fields = req.body;
  const keys = Object.keys(fields);
  if (!keys.length) return res.json({ success: true });

  const values = Object.values(fields);
  const setString = keys.map((k,i)=>`${k}=$${i+1}`).join(",");
  try {
    await pool.query(`UPDATE users SET ${setString} WHERE id=$${keys.length+1}`, [...values, req.session.userId]);
    res.json({ success: true });
  } catch(err){
    res.status(500).json({ error: err.message });
  }
});

// --- Products & Cart ---
app.get("/api/products", async (req, res) => {
  const result = await pool.query("SELECT * FROM products");
  res.json(result.rows);
});

app.get("/api/cart", requireAuth, async (req, res) => {
  const result = await pool.query(`
    SELECT c.id, p.name, p.price, c.qty 
    FROM carts c JOIN products p ON c.product_id=p.id
    WHERE c.user_id=$1
  `, [req.session.userId]);
  res.json(result.rows);
});

app.post("/api/cart/add", requireAuth, async (req, res) => {
  const { id } = req.body;
  const existing = await pool.query("SELECT * FROM carts WHERE user_id=$1 AND product_id=$2", [req.session.userId, id]);
  if (existing.rows[0]) {
    await pool.query("UPDATE carts SET qty=qty+1 WHERE user_id=$1 AND product_id=$2", [req.session.userId, id]);
  } else {
    await pool.query("INSERT INTO carts (user_id, product_id, qty) VALUES ($1,$2,1)", [req.session.userId, id]);
  }
  res.json({ success: true });
});

app.post("/api/cart/remove", requireAuth, async (req, res) => {
  const { id } = req.body;
  await pool.query("DELETE FROM carts WHERE id=$1 AND user_id=$2", [id, req.session.userId]);
  res.json({ success: true });
});

app.post("/api/cart/checkout", requireAuth, async (req, res) => {
  const cartItems = await pool.query("SELECT * FROM carts WHERE user_id=$1", [req.session.userId]);
  for (let item of cartItems.rows) {
    await pool.query("INSERT INTO orders (user_id, product_id, qty) VALUES ($1,$2,$3)", [req.session.userId, item.product_id, item.qty]);
  }
  await pool.query("DELETE FROM carts WHERE user_id=$1", [req.session.userId]);
  res.json({ success: true });
});

// --- Orders ---
app.get("/api/orders", requireAuth, async (req, res) => {
  const orders = await pool.query(`
    SELECT o.id, p.name, p.price, o.qty 
    FROM orders o JOIN products p ON o.product_id=p.id
    WHERE o.user_id=$1 ORDER BY o.created_at DESC
  `, [req.session.userId]);
  res.json(orders.rows);
});

// --- Start ---
app.listen(PORT, async () => {
  console.log(`✅ Server started on ${PORT}`);
  await initDB();
});
