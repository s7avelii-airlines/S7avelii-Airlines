// server.js
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import pkg from "pg";

dotenv.config();
const { Pool } = pkg;

const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || "change_this_secret";
const STATIC_ORIGIN = process.env.STATIC_ORIGIN || "*"; // укажи домен статики, например https://www.s7avelii-airlines.ru

// Pool для Neon/Postgres
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const app = express();
app.use(express.json());
app.use(cors({
  origin: STATIC_ORIGIN,
  methods: ["GET","POST","PUT","DELETE","OPTIONS"],
  allowedHeaders: ["Content-Type","Authorization"],
}));

// --- health / debug ---
app.get("/api/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ ok: true });
  } catch (err) {
    console.error("health err:", err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// --- init DB (safe create) ---
async function initDB(){
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        fio TEXT,
        email TEXT UNIQUE,
        phone TEXT,
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

    // seed products if empty
    const r = await pool.query("SELECT COUNT(*) FROM products");
    if (Number(r.rows[0].count) === 0) {
      await pool.query(`
        INSERT INTO products (name, price) VALUES
        ('Брелок S7avelii', 500),
        ('Футболка S7avelii', 1200),
        ('Кружка S7avelii', 800),
        ('Модель самолёта', 2500);
      `);
    }
    console.log("DB initialized");
  } catch (err) {
    console.error("DB init failed:", err);
    throw err;
  }
}
initDB().catch(()=>{ /* init error logged above */ });

// --- helpers ---
function signToken(userId){
  return jwt.sign({ id: userId }, JWT_SECRET, { expiresIn: "7d" });
}
async function getUserById(id){
  const { rows } = await pool.query("SELECT * FROM users WHERE id=$1", [id]);
  return rows[0] || null;
}
function authMiddleware(req, res, next){
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

// --- register --- (accepts fio,email,phone,password,dob,gender,cardNumber,cardType)
app.post("/api/register", async (req, res) => {
  try {
    const { fio, email, phone, password, dob, gender, cardNumber, cardType } = req.body;
    if (!email || !password || !fio) return res.status(400).json({ error: "fio,email,password required" });

    // check existing by email or phone
    const check = await pool.query("SELECT id FROM users WHERE email=$1 OR phone=$2", [email, phone]);
    if (check.rows.length) return res.status(400).json({ error: "User exists" });

    const hash = await bcrypt.hash(password, 10);
    const ins = await pool.query(
      `INSERT INTO users (fio,email,phone,password,dob,gender,card_number,card_type,bonus_miles,status_miles)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,0,0) RETURNING id`,
      [fio,email,phone,hash,dob||null,gender||null,cardNumber||null,cardType||null]
    );
    const token = signToken(ins.rows[0].id);
    res.json({ token });
  } catch (err) {
    console.error("register err:", err);
    res.status(500).json({ error: "Registration failed" });
  }
});

// --- login --- (accepts phone OR email + password)
app.post("/api/login", async (req, res) => {
  try {
    const { identifier, password, phone, email } = req.body;
    // support phone or email; some frontends send phone
    let userRow;
    if (phone || identifier) {
      const key = phone || identifier;
      const r = await pool.query("SELECT * FROM users WHERE phone=$1", [key]);
      userRow = r.rows[0];
    } else if (email) {
      const r = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
      userRow = r.rows[0];
    } else {
      // try email in identifier
      if (identifier) {
        const r = await pool.query("SELECT * FROM users WHERE email=$1 OR phone=$1", [identifier]);
        userRow = r.rows[0];
      }
    }
    if (!userRow) return res.status(400).json({ error: "User not found" });
    const ok = await bcrypt.compare(password, userRow.password);
    if (!ok) return res.status(400).json({ error: "Wrong password" });
    const token = signToken(userRow.id);
    res.json({ token });
  } catch (err) {
    console.error("login err:", err);
    res.status(500).json({ error: "Login failed" });
  }
});

// --- profile get ---
app.get("/api/profile", authMiddleware, async (req, res) => {
  try {
    const user = await getUserById(req.userId);
    if (!user) return res.status(404).json({ error: "Not found" });
    delete user.password;
    res.json(user);
  } catch (err) {
    console.error("profile err:", err);
    res.status(500).json({ error: "Profile error" });
  }
});

// --- profile update ---
app.post("/api/profile/update", authMiddleware, async (req, res) => {
  try {
    const body = req.body;
    const sets = [];
    const vals = [];
    let i = 1;
    if ("password" in body) {
      const hash = await bcrypt.hash(body.password, 10);
      sets.push(`password=$${i++}`); vals.push(hash);
      delete body.password;
    }
    for (const k of Object.keys(body)) {
      // allow only known fields
      if (["fio","email","phone","dob","gender","avatar","card_number","card_type","vk","telegram","bonus_miles","status_miles"].includes(k)) {
        sets.push(`${k}=$${i++}`);
        vals.push(body[k]);
      }
    }
    if (!sets.length) return res.json({ ok: true });
    vals.push(req.userId);
    await pool.query(`UPDATE users SET ${sets.join(",")} WHERE id=$${i}`, vals);
    res.json({ ok: true });
  } catch (err) {
    console.error("profile.update err:", err);
    res.status(500).json({ error: "Update failed" });
  }
});

// --- products ---
app.get("/api/products", async (req, res) => {
  try {
    const r = await pool.query("SELECT * FROM products ORDER BY id");
    res.json(r.rows);
  } catch (err) {
    console.error("products err:", err);
    res.status(500).json({ error: "Products error" });
  }
});

// --- cart stored in users.cart JSONB ---
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
    if (found) found.qty = (found.qty||1) + 1;
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

app.post("/api/cart/checkout", authMiddleware, async (req, res) => {
  try {
    const r = await pool.query("SELECT cart FROM users WHERE id=$1", [req.userId]);
    const cart = r.rows[0].cart || [];
    if (!cart.length) return res.status(400).json({ error: "Cart empty" });
    await pool.query("INSERT INTO orders (user_id, items) VALUES ($1,$2)", [req.userId, JSON.stringify(cart)]);
    await pool.query("UPDATE users SET cart = '[]' WHERE id=$1", [req.userId]);
    // optional: add bonus miles
    await pool.query("UPDATE users SET bonus_miles = COALESCE(bonus_miles,0) + 100 WHERE id=$1", [req.userId]);
    res.json({ ok: true });
  } catch (err) {
    console.error("cart.checkout err:", err);
    res.status(500).json({ error: "Checkout error" });
  }
});

// --- orders ---
app.get("/api/orders", authMiddleware, async (req, res) => {
  try {
    const r = await pool.query("SELECT * FROM orders WHERE user_id=$1 ORDER BY id DESC", [req.userId]);
    res.json(r.rows);
  } catch (err) {
    console.error("orders err:", err);
    res.status(500).json({ error: "Orders error" });
  }
});

// fallback static (if you host static from same server)
app.use(express.static("public"));

app.listen(PORT, () => console.log(`✅ Server started on ${PORT}`));
